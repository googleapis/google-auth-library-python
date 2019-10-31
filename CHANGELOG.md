# Changelog

[PyPI History][1]

[1]: https://pypi.org/project/DISTRIBUTION NAME/#history

## 1.7.0

10-30-2019 17:11 PDT


### Implementation Changes
- Add retry loop  for fetching authentication token if any 'Internal Failure' occurs ([#368](https://github.com/googleapis/google-auth-library-python/pull/368))
- Use cls parameter instead of class ([#341](https://github.com/googleapis/google-auth-library-python/pull/341))

### New Features
- Add support for `impersonated_credentials.Sign`, `IDToken` ([#348](https://github.com/googleapis/google-auth-library-python/pull/348))
- Add downscoping to OAuth2 credentials ([#309](https://github.com/googleapis/google-auth-library-python/pull/309))

### Dependencies
- Update dependency cachetools to v3 ([#357](https://github.com/googleapis/google-auth-library-python/pull/357))
- Update dependency rsa to v4 ([#358](https://github.com/googleapis/google-auth-library-python/pull/358))
- Set an upper bound on dependencies version ([#352](https://github.com/googleapis/google-auth-library-python/pull/352))
- Require a minimum version of setuptools ([#322](https://github.com/googleapis/google-auth-library-python/pull/322))

### Documentation
- Add busunkim96 as maintainer ([#373](https://github.com/googleapis/google-auth-library-python/pull/373))
- Update user-guide.rst ([#337](https://github.com/googleapis/google-auth-library-python/pull/337))
- Fix typo in jwt docs ([#332](https://github.com/googleapis/google-auth-library-python/pull/332))
- Clarify which SA has Token Creator role ([#330](https://github.com/googleapis/google-auth-library-python/pull/330))

### Internal / Testing Changes
- Change 'name' to distribution name ([#379](https://github.com/googleapis/google-auth-library-python/pull/379))
- Fix system tests, move to Kokoro ([#372](https://github.com/googleapis/google-auth-library-python/pull/372))
- Blacken ([#375](https://github.com/googleapis/google-auth-library-python/pull/375))
- Rename nox.py -> noxfile.py ([#369](https://github.com/googleapis/google-auth-library-python/pull/369))
- Add initial renovate config ([#356](https://github.com/googleapis/google-auth-library-python/pull/356))
- Use new pytest api to keep building with pytest 5 ([#353](https://github.com/googleapis/google-auth-library-python/pull/353))

