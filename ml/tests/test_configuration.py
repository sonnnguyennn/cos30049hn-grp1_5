from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def load_yaml(relative_path: str) -> dict:
    path = PROJECT_ROOT / relative_path
    with path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle)
    assert isinstance(loaded, dict)
    return loaded


def test_project_config_loads_with_accepted_data_roles() -> None:
    config = load_yaml("config/project.yaml")

    assert config["project"]["name"] == "IoTGuard"
    assert config["ml"]["primary_task"]["target_form"] == "binary_benign_vs_malicious"
    assert config["data"]["primary_dataset"] == "n_baiot"
    assert config["data"]["secondary_datasets"] == ["bot_iot"]


def test_data_path_schema_contains_accepted_dataset_roles() -> None:
    config = load_yaml("config/data_paths.example.yaml")
    datasets = config["datasets"]

    assert set(datasets) == {"bot_iot", "n_baiot"}
    assert all(dataset["root"] for dataset in datasets.values())
    assert datasets["n_baiot"]["role"] == "primary"
    assert datasets["bot_iot"]["role"] == "secondary"
