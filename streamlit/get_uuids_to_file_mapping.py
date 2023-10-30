import yaml
import glob
import json


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


# Note: Future me please merge these functions as you did in a hurry :)
def get_uuids(file_list):
    uuids = []
    for file in file_list:
        id = get_rule_part(file, "id")
        if id:
            uuids.append(id)
    return uuids


def get_uuids_to_file_mapping(file_list):
    mapping = {}
    for file in file_list:
        id = get_rule_part(file, "id")
        mapping[id] = file
        mapping[file] = id
    return mapping


if __name__ == "__main__":
    file_list = glob.glob("rules/**/*.yml", recursive=True) + glob.glob(
        "rules-*/**/*.yml", recursive=True
    )
    uuids = get_uuids(file_list)
    with open("streamlit/rules_uuid.txt", "w") as f:
        for id in uuids:
            f.write(id + "\n")

    mapping = get_uuids_to_file_mapping(file_list)
    with open("streamlit/uuids_filename_mappings.json", "w") as f:
        f.write(json.dumps(mapping))
