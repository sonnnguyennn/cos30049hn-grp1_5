import json
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from iotguard.evaluation.primary import (
    binary_metrics,
    experiment_result,
    resolve_configuration,
    select_validation,
)


@pytest.fixture
def result():
    return experiment_result(
        "regression", binary_metrics([0, 1], [0.1, 0.9]),
        configuration=resolve_configuration(input_view="raw", parameters={}),
        code_revision="test-revision", package_version="primary_package_v1",
        package_manifest_sha256="a" * 64, dirty_worktree=False,
        train_population_sha256="b" * 64, validation_population_sha256="c" * 64)


@pytest.fixture
def validator():
    schema = json.loads((Path(__file__).resolve().parents[2]
                         / "docs/protocols/primary_result_v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def test_complete_result_matches_schema(result, validator):
    validator.validate(result)
    dirty = deepcopy(result)
    dirty["dirty_worktree"] = True
    validator.validate(dirty)
    assert select_validation([result, dirty]) is result


@pytest.mark.parametrize("field", ["package_version", "package_manifest_sha256",
                                    "protocol_revision", "train_population_sha256",
                                    "validation_population_sha256"])
def test_selection_refuses_different_identity(result, field):
    other = deepcopy(result)
    other[field] = "d" * 64 if field.endswith("sha256") else "another-version"
    if field == "protocol_revision":
        other["resolved_configuration"]["protocol_revision"] = other[field]
    with pytest.raises(ValueError, match="identical package, protocol and populations"):
        select_validation([result, other])


@pytest.mark.parametrize("field", ["package_version", "package_manifest_sha256",
                                    "dirty_worktree", "protocol_revision",
                                    "train_population_sha256", "validation_population_sha256"])
def test_selection_and_schema_refuse_missing_identity(result, validator, field):
    del result[field]
    with pytest.raises(ValueError, match="Missing required experiment identity"):
        select_validation([result])
    with pytest.raises(ValidationError):
        validator.validate(result)


@pytest.mark.parametrize("field,value", [("package_version", ""),
                                          ("package_manifest_sha256", "bad-hash"),
                                          ("dirty_worktree", "clean"),
                                          ("dirty_worktree", None)])
def test_constructor_and_schema_refuse_invalid_identity(result, validator, field, value):
    arguments = {k: result[k] for k in ("code_revision", "package_version",
                 "package_manifest_sha256", "dirty_worktree", "train_population_sha256",
                 "validation_population_sha256")}
    arguments[field] = value
    with pytest.raises(ValueError):
        experiment_result("x", result["metrics"],
                          configuration=result["resolved_configuration"], **arguments)
    result[field] = value
    with pytest.raises(ValidationError):
        validator.validate(result)


@pytest.mark.parametrize("field", ["package_version", "package_manifest_sha256", "dirty_worktree"])
def test_constructor_requires_new_keywords(result, field):
    arguments = {k: result[k] for k in ("code_revision", "package_version",
                 "package_manifest_sha256", "dirty_worktree", "train_population_sha256",
                 "validation_population_sha256")}
    del arguments[field]
    with pytest.raises(TypeError):
        experiment_result("x", result["metrics"],
                          configuration=result["resolved_configuration"], **arguments)
