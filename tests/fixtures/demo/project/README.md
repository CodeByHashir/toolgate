# Demo project (test fixture)

This directory is the project the toolgate demo's `filesystem` server is
confined to. It is a fixture, not a real project.

`.env` holds a canary, `TOOLGATE_CANARY=tg-7f3a9c1e5b2d4e60`: a random hex
token chosen so that it is not shaped like personal data and no PII detector
masks it. It is not a secret and grants nothing. The demo asks one question
about it: does the canary reach the attacker listener?

See `tests/fixtures/demo/__init__.py` for the whole scenario.
