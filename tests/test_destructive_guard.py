from scanner.core.config import (
    BflaAttackConfig,
    BflaConfig,
    BflaTestConfig,
    BolaAttackConfig,
    BolaConfig,
    BolaResourceConfig,
    BolaTestConfig,
    PropertyAuthConfig,
    PropertyAuthTestConfig,
    PropertyPayloadConfig,
    PropertyRequestConfig,
)
from scanner.core.destructive import filter_destructive_tests
from tests.test_scanner_main import build_config


def test_filter_destructive_tests_skips_marked_tests_and_payloads() -> None:
    config = build_config()
    config.bola = BolaConfig(
        tests=[
            BolaTestConfig(
                name="read_other_resource",
                role="user",
                owner_field="owner_id",
                resource=BolaResourceConfig(
                    list_method="GET",
                    list_path="/resources",
                    id_field="id",
                ),
                attack=BolaAttackConfig(method="GET", path_template="/resources/{id}"),
                expected_status=403,
            ),
            BolaTestConfig(
                name="delete_other_resource",
                role="user",
                owner_field="owner_id",
                resource=BolaResourceConfig(
                    list_method="GET",
                    list_path="/resources",
                    id_field="id",
                ),
                attack=BolaAttackConfig(method="DELETE", path_template="/resources/{id}"),
                expected_status=403,
                destructive=True,
                reset_recommended=True,
            ),
        ]
    )
    config.bfla = BflaConfig(
        tests=[
            BflaTestConfig(
                name="refund_order",
                role="user",
                attack=BflaAttackConfig(method="POST", path_template="/orders/{id}/refund"),
                expected_status=403,
                destructive=True,
                reset_recommended=True,
            )
        ]
    )
    config.property_auth = PropertyAuthConfig(
        tests=[
            PropertyAuthTestConfig(
                name="create_resource_must_not_accept_server_fields",
                type="mass_assignment",
                role="user",
                request=PropertyRequestConfig(method="POST", path_template="/resources"),
                payloads=[
                    PropertyPayloadConfig(
                        name="safe_payload",
                        json_body={"name": "normal"},
                    ),
                    PropertyPayloadConfig(
                        name="force_approved",
                        json_body={"state": "approved"},
                        forbidden_effects={"state": "approved"},
                        destructive=True,
                        reset_recommended=True,
                    ),
                ],
            )
        ]
    )

    filtered_config, skipped_tests = filter_destructive_tests(config)

    assert [test.name for test in filtered_config.bola.tests] == ["read_other_resource"]
    assert filtered_config.bfla.tests == []
    assert [payload.name for payload in filtered_config.property_auth.tests[0].payloads] == [
        "safe_payload"
    ]
    assert [skipped_test.name for skipped_test in skipped_tests] == [
        "delete_other_resource",
        "refund_order",
        "create_resource_must_not_accept_server_fields:force_approved",
    ]
    assert all(skipped_test.destructive for skipped_test in skipped_tests)
    assert all(skipped_test.reset_recommended for skipped_test in skipped_tests)


def test_filter_destructive_tests_keeps_all_tests_when_explicitly_included() -> None:
    config = build_config()
    config.bola.tests[0].destructive = True

    filtered_config, skipped_tests = filter_destructive_tests(
        config,
        include_destructive=True,
    )

    assert filtered_config is config
    assert skipped_tests == []
