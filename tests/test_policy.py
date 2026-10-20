from __future__ import annotations

import pytest

from xacct.policy import PolicyError, action_matches, parse_statements


def test_single_statement_object_and_string_fields() -> None:
    [st] = parse_statements(
        '{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject",'
        '"Resource":"arn:aws:s3:::b/*"}}'
    )
    assert st.sid == "#0"
    assert st.actions == ("s3:GetObject",)
    assert st.resources == ("arn:aws:s3:::b/*",)
    assert st.allows


def test_condition_keys_are_case_insensitive_and_values_normalized() -> None:
    [st] = parse_statements(
        {
            "Statement": [
                {
                    "Sid": "T",
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
                    "Condition": {
                        "StringEquals": {"STS:ExternalId": "abc"},
                        "Bool": {"aws:MultiFactorAuthPresent": True},
                    },
                }
            ]
        }
    )
    assert st.condition("sts:externalid") == [("StringEquals", ("abc",))]
    assert st.condition("aws:MultiFactorAuthPresent") == [("Bool", ("true",))]
    assert st.principals == {"AWS": ("arn:aws:iam::111111111111:root",)}


def test_principal_star_and_not_principal() -> None:
    a, b = parse_statements(
        {
            "Statement": [
                {"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"},
                {"Effect": "Allow", "NotPrincipal": {"AWS": "x"}, "Action": "sts:AssumeRole"},
            ]
        }
    )
    assert a.principals == {"*": ("*",)}
    assert b.not_principal


@pytest.mark.parametrize(
    ("pattern", "action", "expected"),
    [
        ("iam:Put*", "iam:PutRolePolicy", True),
        ("IAM:passrole", "iam:PassRole", True),
        ("s3:Get?bject", "s3:GetObject", True),
        ("s3:GetObject", "s3:PutObject", False),
        ("*", "anything:AtAll", True),
    ],
)
def test_action_matches(pattern: str, action: str, expected: bool) -> None:
    assert action_matches(pattern, action) is expected


@pytest.mark.parametrize(
    "doc",
    [
        "not json",
        '{"Version":"2012-10-17"}',
        '{"Statement":[{"Effect":"Maybe"}]}',
        '{"Statement":[{"Effect":"Allow","Principal":["x"]}]}',
        '{"Statement":[{"Effect":"Allow","Condition":"x"}]}',
        '{"Statement":[{"Effect":"Allow","Condition":{"StringEquals":"x"}}]}',
        "[]",
    ],
)
def test_invalid_documents(doc: str) -> None:
    with pytest.raises(PolicyError):
        parse_statements(doc)
