# 52ab5108-3f6f-42fb-8ba3-73bc054f22c8

import os
import yaml
from colorama import init
from colorama import Fore
import subprocess

path_to_rules = ["rules"]


# Helper functions
def yield_next_rule_file_path(path_to_rules: list) -> str:
    for path_ in path_to_rules:
        for root, _, files in os.walk(path_):
            for file in files:
                if file.endswith(".yml"):
                    yield os.path.join(root, file)


def get_rule_part(file_path: str, part_name: str):
    yaml_dicts = get_rule_yaml(file_path)
    for yaml_part in yaml_dicts:
        if part_name in yaml_part.keys():
            return yaml_part[part_name]

    return None


def get_rule_yaml(file_path: str) -> dict:
    data = []

    with open(file_path, encoding="utf-8") as f:
        yaml_parts = yaml.safe_load_all(f)
        for part in yaml_parts:
            data.append(part)

    return data


def run_pwsh_cmd(cmd):
    status = subprocess.run(["powershell", "-Command", cmd], capture_output=True)
    return status


def logsource_mapper():
    pass


for file in yield_next_rule_file_path(path_to_rules):
    regression_tests_list = get_rule_part(file_path=file, part_name="regression")
    if regression_tests_list:
        if not isinstance(regression_tests_list, list):
            pass  # Throw error
        else:
            for test in regression_tests_list:
                if test["type"] == "atomic-red-team":
                    atomic_id = test["id"]
                    print(atomic_id)
                    output = run_pwsh_cmd("Invoke-AtomicTest T1003 -ShowDetailsBrief")
                    print(output)
