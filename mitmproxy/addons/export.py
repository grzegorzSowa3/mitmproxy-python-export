import base64
import io
import json
import logging
import re
import shlex
from collections.abc import Callable
from collections.abc import Sequence
from typing import Any

import pyperclip
from werkzeug.formparser import FormDataParser
from werkzeug.formparser import MultiPartParser

import mitmproxy.types
from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import flow
from mitmproxy import http
from mitmproxy.net.http.http1 import assemble
from mitmproxy.utils import strutils


def cleanup_request(f: flow.Flow) -> http.Request:
    if not getattr(f, "request", None):
        raise exceptions.CommandError("Can't export flow with no request.")
    assert isinstance(f, http.HTTPFlow)
    request = f.request.copy()
    request.decode(strict=False)
    return request


def pop_headers(request: http.Request) -> http.Request:
    # Remove some headers that are redundant for curl/httpie export
    request.headers.pop("content-length")
    if request.headers.get("host", "") == request.host:
        request.headers.pop("host")
    if request.headers.get(":authority", "") == request.host:
        request.headers.pop(":authority")
    return request


def cleanup_response(f: flow.Flow) -> http.Response:
    if not getattr(f, "response", None):
        raise exceptions.CommandError("Can't export flow with no response.")
    assert isinstance(f, http.HTTPFlow)
    response = f.response.copy()  # type: ignore
    response.decode(strict=False)
    return response


def request_content_for_console(request: http.Request) -> str:
    try:
        text = request.get_text(strict=True)
        assert text
    except ValueError:
        # shlex.quote doesn't support a bytes object
        # see https://github.com/python/cpython/pull/10871
        raise exceptions.CommandError("Request content must be valid unicode")
    escape_control_chars = {chr(i): f"\\x{i:02x}" for i in range(32)}
    return "".join(escape_control_chars.get(x, x) for x in text)


def curl_command(f: flow.Flow) -> str:
    request = cleanup_request(f)
    request = pop_headers(request)
    args = ["curl"]

    server_addr = f.server_conn.peername[0] if f.server_conn.peername else None

    if (
            ctx.options.export_preserve_original_ip
            and server_addr
            and request.pretty_host != server_addr
    ):
        resolve = f"{request.pretty_host}:{request.port}:[{server_addr}]"
        args.append("--resolve")
        args.append(resolve)

    for k, v in request.headers.items(multi=True):
        if k.lower() == "accept-encoding":
            args.append("--compressed")
        else:
            args += ["-H", f"{k}: {v}"]

    if request.method != "GET":
        args += ["-X", request.method]

    args.append(request.pretty_url)

    if request.content:
        args += ["-d", request_content_for_console(request)]
    return " ".join(shlex.quote(arg) for arg in args)


def httpie_command(f: flow.Flow) -> str:
    request = cleanup_request(f)
    request = pop_headers(request)

    # TODO: Once https://github.com/httpie/httpie/issues/414 is implemented, we
    # should ensure we always connect to the IP address specified in the flow,
    # similar to how it's done in curl_command.
    url = request.pretty_url

    args = ["http", request.method, url]
    for k, v in request.headers.items(multi=True):
        args.append(f"{k}: {v}")
    cmd = " ".join(shlex.quote(arg) for arg in args)
    if request.content:
        cmd += " <<< " + shlex.quote(request_content_for_console(request))
    return cmd


def raw_request(f: flow.Flow) -> bytes:
    request = cleanup_request(f)
    if request.raw_content is None:
        raise exceptions.CommandError("Request content missing.")
    return assemble.assemble_request(request)


def raw_response(f: flow.Flow) -> bytes:
    response = cleanup_response(f)
    if response.raw_content is None:
        raise exceptions.CommandError("Response content missing.")
    return assemble.assemble_response(response)


def raw(f: flow.Flow, separator=b"\r\n\r\n") -> bytes:
    """Return either the request or response if only one exists, otherwise return both"""
    request_present = (
            isinstance(f, http.HTTPFlow) and f.request and f.request.raw_content is not None
    )
    response_present = (
            isinstance(f, http.HTTPFlow)
            and f.response
            and f.response.raw_content is not None
    )

    if request_present and response_present:
        parts = [raw_request(f), raw_response(f)]
        if isinstance(f, http.HTTPFlow) and f.websocket:
            parts.append(f.websocket._get_formatted_messages())
        return separator.join(parts)
    elif request_present:
        return raw_request(f)
    elif response_present:
        return raw_response(f)
    else:
        raise exceptions.CommandError("Can't export flow with no request or response.")


def python_script(f: flow.Flow) -> str:
    request = cleanup_request(f)
    imports = [
        "import http.client",
    ]
    data = [
        "", "",
        "def %s_%s() -> http.client.HTTPResponse:" % (
            request.method, "_".join(request.path_components).replace('-', '')
        ),
        "    method, path = '%s', '/%s'" % (request.method, "/".join(request.path_components)),
        "    host, port = '%s', %s" % (request.host, request.port),
    ]
    if request.query:
        data.append("    query_params = [")
        for name, value in request.query.items(multi=True):
            data.append(f"        ('{name}', '{value}'),")
        data.append("    ]")
    headers = ["    headers = {", ]
    for header in request.headers.fields:
        if header[0].decode('utf-8').casefold() != 'content-length':
            headers.append(f"        '{header[0].decode('utf-8')}': '{header[1].decode('utf-8')}',")
    headers.append("    }")
    data += headers

    body, body_imports = python_script_body(request)
    imports.extend(body_imports)
    for line in body:
        data.append(f"    {line}")
    data.append("    headers['Content-Length'] = str(len(body))")

    if 'https' in request.scheme.casefold():
        data.append(
            "    connection = http.client.HTTPSConnection(host, port, context=ssl._create_unverified_context())")
        imports.append("import ssl")
    else:
        data.append("    connection = http.client.HTTPConnection(host, port)")

    if request.query:
        imports.append("import urllib")
        data.append("""    connection.request(method, f"{path}?{urllib.parse.urlencode(query_params)}", body, headers)""")
    else:
        data.append("    connection.request(method, path, body, headers)")

    data.append("    return connection.getresponse()")
    data.append("")

    return "\n".join(imports + data)


multipart_boundary_re = re.compile(".*boundary=(.*)", re.IGNORECASE)


# return lines and imports
def python_script_body(
        request: http.Request,
) -> tuple[list[str], list[str]]:
    content_type = None
    if 'content-type' in request.headers.keys():
        content_type = request.headers['content-type']
    content_length = int(request.headers['content-length'])
    if content_type is not None and 'multipart' in content_type:
        fields = ["fields = {"]
        files = ["files = {"]

        parser = MultiPartParser()
        boundary = multipart_boundary_re.findall(content_type)[0]
        fields_extracted, files_extracted = parser.parse(
            stream=io.BytesIO(request.content),
            boundary=boundary.encode("utf-8"),
            content_length=content_length,
        )
        for field_name, field_value in fields_extracted.items():
            fields.append(
                f"    '{field_name}': '{field_value}',"
            )
        for field_name, file in files_extracted.items():
            files.append(
                f"    '{field_name}': " + '{'
            ),
            files.append(
                f"        'filename': '{file.filename}',"
            )
            files.append(
                f"        'content_type': '{file.content_type}',"
            )
            files.append(
                f"        'content': \"\"\"{base64.encodebytes(file.stream.read()).decode('utf-8')}\"\"\","
            )
            files.append("    },")
        fields.append("}")
        files.append("}")
        imports = [
            "import io",
            "import base64",
            "from werkzeug.test import encode_multipart",
            "from werkzeug.datastructures.file_storage import FileStorage",
        ]
        lines = fields + files
        lines += [
            "_, body = encode_multipart(",
            f"    boundary='{boundary}',",
            "    values={",
            "        field_name: field_value",
            "        for field_name, field_value in fields.items()",
            "    } | {",
            "        field_name: FileStorage(",
            "            filename=file['filename'],",
            "            content_type=file['content_type'],",
            "            stream=io.BytesIO(base64.decodebytes(file['content'].encode('utf-8'))),",
            "        ) for field_name, file in files.items()",
            "    },",
            ")",
        ]
        return lines, imports

    if content_type is not None and 'x-www-form-urlencoded' in content_type:
        lines = ["fields = ["]
        parser = FormDataParser()
        _, fields_extracted, _ = parser.parse(
            stream=io.BytesIO(request.content),
            mimetype="application/x-www-form-urlencoded",
            content_length=content_length,
        )
        for field_name, field_value in fields_extracted.items():
            lines.append(
                f"    ('{field_name}', '{field_value}'),"
            )
        lines.append("]")
        imports = [
            "import urllib.parse"
        ]
        lines.append("body = urllib.parse.urlencode(fields)")
        return lines, imports

    if content_type is not None and 'json' in content_type:
        lines = ["{", "}"]
        request_body = request.content.decode('utf-8')
        if len(request_body) > 0:
            lines = json_lines(json.loads(request_body))
        lines[0] = "fields = " + lines[0]
        imports = [
            "import json"
        ]
        lines.append("body = json.dumps(fields)")
        return lines, imports

    try:
        return (
            ["body = '%s'" % request.content.decode('utf-8')],
            [],
        )
    except UnicodeDecodeError:
        pass
    imports = []
    body_bytes = [
        "body_base64 = \"\"\"%s\"\"\"" % base64.encodebytes(request.content).decode('utf-8'),
        "body = base64.decodebytes(body_base64.encode('utf-8'))"
    ]
    imports.append("import base64")
    return (
        body_bytes,
        imports,
    )


formats: dict[str, Callable[[flow.Flow], str | bytes]] = dict(
    curl=curl_command,
    httpie=httpie_command,
    raw=raw,
    raw_request=raw_request,
    raw_response=raw_response,
    python_script=python_script,
)


def json_lines(obj) -> list[str]:
    if type(obj) is list:
        return json_list_lines(obj)
    elif type(obj) is dict:
        return json_dict_lines(obj)
    elif type(obj) is str:
        return json_string_lines(obj)
    else:
        return [str(obj)]


def json_list_lines(lst: list) -> list[str]:
    lines = ["["]
    for item in lst:
        for line in json_lines(item):
            lines.append("    " + line)
        lines[-1] = lines[-1] + ','
    lines.append("]")
    return lines


def json_dict_lines(dct: dict) -> list[str]:
    lines = ["{"]
    for key, value in dct.items():
        first = True
        for line in json_lines(value):
            if first:
                lines.append(f""""{key}": {line}""")
                first = False
            else:
                lines.append("    " + line)
        lines[-1] = lines[-1] + ','
    lines.append("}")
    return lines


def json_string_lines(string: str) -> list[str]:
    if '\n' not in string:
        return [f"\"{string}\""]
    lines = ["f\"\"\""]
    for line in string.split("\n"):
        lines.append("    " + line.replace('{', '{{').replace('}', '}}'))
    lines.append("\"\"\"")
    return lines


class Export:
    def load(self, loader):
        loader.add_option(
            "export_preserve_original_ip",
            bool,
            False,
            """
            When exporting a request as an external command, make an effort to
            connect to the same IP as in the original request. This helps with
            reproducibility in cases where the behaviour depends on the
            particular host we are connecting to. Currently this only affects
            curl exports.
            """,
        )

    @command.command("export.formats")
    def formats(self) -> Sequence[str]:
        """
        Return a list of the supported export formats.
        """
        return list(sorted(formats.keys()))

    @command.command("export.file")
    def file(self, format: str, flow: flow.Flow, path: mitmproxy.types.Path) -> None:
        """
        Export a flow to path.
        """
        if format not in formats:
            raise exceptions.CommandError("No such export format: %s" % format)
        func: Any = formats[format]
        v = func(flow)
        try:
            with open(path, "wb") as fp:
                if isinstance(v, bytes):
                    fp.write(v)
                else:
                    fp.write(v.encode("utf-8"))
        except OSError as e:
            logging.error(str(e))

    @command.command("export.clip")
    def clip(self, format: str, f: flow.Flow) -> None:
        """
        Export a flow to the system clipboard.
        """
        try:
            pyperclip.copy(self.export_str(format, f))
        except pyperclip.PyperclipException as e:
            logging.error(str(e))

    @command.command("export")
    def export_str(self, format: str, f: flow.Flow) -> str:
        """
        Export a flow and return the result.
        """
        if format not in formats:
            raise exceptions.CommandError("No such export format: %s" % format)
        func = formats[format]

        return strutils.always_str(func(f), "utf8", "backslashreplace")
