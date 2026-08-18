# Ponse [![License][LicenseIMGURL]][LicenseURL] [![NPM version][NPMIMGURL]][NPMURL] [![Build Status][BuildStatusIMGURL]][BuildStatusURL] [![Coverage Status][CoverageIMGURL]][CoverageURL]

[NPMURL]: https://npmjs.org/package/ponse "npm"
[NPMIMGURL]: https://img.shields.io/npm/v/ponse.svg?style=flat
[BuildStatusURL]: https://github.com/coderaiser/ponse/actions?query=workflow%3A%22Node+CI%22 "Build Status"
[BuildStatusIMGURL]: https://github.com/coderaiser/ponse/workflows/Node%20CI/badge.svg
[LicenseURL]: https://tldrlegal.com/license/mit-license "MIT License"
[LicenseIMGURL]: https://img.shields.io/badge/license-MIT-317BF9.svg?style=flat
[CoverageURL]: https://coveralls.io/github/coderaiser/ponse?branch=master
[CoverageIMGURL]: https://coveralls.io/repos/coderaiser/ponse/badge.svg?branch=master&service=github

Module for work with requests and responses

## Install

`npm i ponse --save`

## Api

**isGZIP(request)** check is gzip supported

- http request

**getPathName(request || string)** - get pathname

- http request

**getQuery(request || string)** - get query

- http request

**createStatic(options)** - serve static content

- options:
  - cache
  - root

**send(data, params)** - send data

## License

MIT
