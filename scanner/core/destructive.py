from pydantic import BaseModel

from scanner.core.config import (
    BflaConfig,
    BolaConfig,
    PropertyAuthConfig,
    PropertyAuthTestConfig,
    PropertyPayloadConfig,
    ScannerConfig,
    UnauthenticatedConfig,
)


DESTRUCTIVE_SKIP_REASON = (
    "destructive test skipped by default; rerun with --include-destructive to execute it"
)


class SkippedTest(BaseModel):
    module: str
    name: str
    reason: str
    destructive: bool = False
    reset_recommended: bool = False


def filter_destructive_tests(
    config: ScannerConfig,
    include_destructive: bool = False,
) -> tuple[ScannerConfig, list[SkippedTest]]:
    if include_destructive:
        return config, []

    skipped_tests: list[SkippedTest] = []

    bola_tests = []
    for test in config.bola.tests:
        if test.destructive:
            skipped_tests.append(
                SkippedTest(
                    module="bola",
                    name=test.name,
                    reason=DESTRUCTIVE_SKIP_REASON,
                    destructive=True,
                    reset_recommended=test.reset_recommended,
                )
            )
            continue
        bola_tests.append(test)

    bfla_tests = []
    for test in config.bfla.tests:
        if test.destructive:
            skipped_tests.append(
                SkippedTest(
                    module="bfla",
                    name=test.name,
                    reason=DESTRUCTIVE_SKIP_REASON,
                    destructive=True,
                    reset_recommended=test.reset_recommended,
                )
            )
            continue
        bfla_tests.append(test)

    property_tests: list[PropertyAuthTestConfig] = []
    for test in config.property_auth.tests:
        if test.destructive:
            skipped_tests.append(
                SkippedTest(
                    module="property_auth",
                    name=test.name,
                    reason=DESTRUCTIVE_SKIP_REASON,
                    destructive=True,
                    reset_recommended=test.reset_recommended,
                )
            )
            continue

        payloads: list[PropertyPayloadConfig] = []
        for payload in test.payloads:
            if payload.destructive:
                skipped_tests.append(
                    SkippedTest(
                        module="property_auth",
                        name=f"{test.name}:{payload.name}",
                        reason=DESTRUCTIVE_SKIP_REASON,
                        destructive=True,
                        reset_recommended=payload.reset_recommended or test.reset_recommended,
                    )
                )
                continue
            payloads.append(payload)

        property_tests.append(test.model_copy(update={"payloads": payloads}))

    unauthenticated_tests = []
    for test in config.unauthenticated.tests:
        if test.destructive:
            skipped_tests.append(
                SkippedTest(
                    module="unauthenticated",
                    name=test.name,
                    reason=DESTRUCTIVE_SKIP_REASON,
                    destructive=True,
                    reset_recommended=test.reset_recommended,
                )
            )
            continue
        unauthenticated_tests.append(test)

    filtered_config = config.model_copy(
        update={
            "bola": BolaConfig(tests=bola_tests),
            "bfla": BflaConfig(tests=bfla_tests),
            "property_auth": PropertyAuthConfig(tests=property_tests),
            "unauthenticated": UnauthenticatedConfig(tests=unauthenticated_tests),
        }
    )
    return filtered_config, skipped_tests
