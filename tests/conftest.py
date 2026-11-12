def pytest_addoption(parser):
    parser.addoption(
        "--iam-live", action="store_true",
        help="Opt in to the live Keycloak integration harness.",
    )

    parser.addoption(
        "--journal-postgres", action="store_true",
        help="Run journal tests against an explicitly configured isolated PostgreSQL server.",
    )


def pytest_configure(config):
    config.addinivalue_line("markers", "iam_live: requires --iam-live")
    config.addinivalue_line("markers", "iam_create: requires IAM_ALLOW_CREATE_TEST=1")
    config.addinivalue_line("markers", "journal_postgres: requires --journal-postgres and an isolated database")
