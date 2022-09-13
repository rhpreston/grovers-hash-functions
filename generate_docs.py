# ==========================================================================
# Copyright 2022 The MITRE Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ==========================================================================

import re
from pathlib import Path

INCLUDE_GLOBS = [
    'App/*.qs',
    'App/*/*.qs'
]
OUTPUT_FILE = 'API.md'


def processFile(filename, heading_level):
    namespace = ''
    functions = {}
    current_function = ''
    current_annotation = ''

    f = open(filename, 'r')

    for line in f:
        line = line.strip()

        if not namespace:
            # looking for namespace line
            if line.startswith('namespace'):
                namespace = line.split(' ')[1]
            continue

        if line.startswith('///'):
            # in a comment block
            annotation_line = line[3:].strip()
            if annotation_line.startswith('#'):
                annotation_line = '#' * heading_level + annotation_line
            current_annotation += annotation_line + '\n'
            continue
        if not current_annotation:
            continue

        if not current_function and '(' in line:
            # comment block is over; parse function declaration
            declaration = line.split('(', 1)[0].strip()
            current_function = declaration.split(' ')[-1]
            functions[current_function] = {
                'interface': '',
                'annotation': current_annotation
            }
        if not current_function:
            continue

        if '{' in line:
            # last line of function interface
            functions[current_function]['interface'] += \
                line.split('{', 1)[0].strip()
            current_function = ''
            current_annotation = ''
        else:
            # still in function interface
            functions[current_function]['interface'] += line + ' '

    f.close()
    return (namespace, functions)


def makeLink(full_name):
    return re.sub('\.|\<|\'|\>', '', full_name).lower()


def main(include_globs=INCLUDE_GLOBS, output_file=OUTPUT_FILE):
    heading_level = 3
    title = '# QuICC API Documentation\n'
    copyright = '\n'.join(['',
    'Copyright 2022 The MITRE Corporation',
    '',
    'Licensed under the Apache License, Version 2.0 (the "License");',
    'you may not use this file except in compliance with the License.',
    'You may obtain a copy of the License at',
    '',
    '    http://www.apache.org/licenses/LICENSE-2.0',
    'Unless required by applicable law or agreed to in writing, software',
    'distributed under the License is distributed on an "AS IS" BASIS,',
    'WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.',
    'See the License for the specific language governing permissions and',
    'limitations under the License.',
    ''])
    toc = '\n## Table of Contents\n'
    body = ''
    namespaces = {}

    for include_glob in include_globs:
        for path in Path().glob(include_glob):
            namespace, functions = processFile(path, heading_level)
            if not namespace:
                continue
            if namespace not in namespaces:
                namespaces[namespace] = {}
            namespaces[namespace] = {**namespaces[namespace], **functions}

    for namespace, functions in sorted(namespaces.items()):
        toc += '- [{}](#{})\n'.format(namespace, makeLink(namespace))
        body += '\n## ' + namespace + '\n'
        for function, info in sorted(functions.items()):
            full_name = namespace + '.' + function
            toc += '  - [{}](#{})\n'.format(function, makeLink(full_name))
            body += '\n### {}\n'.format(full_name)
            body += '\n```\n' + info['interface'] + '\n```\n'
            body += '\n' + info['annotation'] + '\n---\n'

    with open(output_file, 'w') as f:
        f.write(title + copyright + toc + body)


if __name__ == '__main__':
    main()
