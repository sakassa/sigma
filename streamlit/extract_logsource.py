import yaml
import os
import json

path_to_rules = [
    "rules",
    "rules-emerging-threats",
    "rules-placeholder",
    "rules-threat-hunting",
    "rules-compliance",
]


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


def gen_logsource_list(path_to_rules):
    product = set()
    service = set()
    category = set()

    logsource = {"product": [], "service": [], "category": []}
    for file in yield_next_rule_file_path(path_to_rules):
        logsource = get_rule_part(file_path=file, part_name="logsource")
        for key, item in logsource.items():
            if key == "product":
                product.add(item)
            elif key == "service":
                service.add(item)
            elif key == "category":
                category.add(item)

    logsource["product"] = sorted(list(product))
    logsource["service"] = sorted(list(service))
    logsource["category"] = sorted(list(category))

    with open("streamlit/logsource_data.json", "w") as f:
        f.write(json.dumps(logsource))


if __name__ == "__main__":
    gen_logsource_list(path_to_rules)
