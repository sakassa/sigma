from datetime import datetime
import streamlit as st
import uuid
import yaml
import glob
import json
from PIL import Image


def test_title(title):
    errors = []
    allowed_lowercase_words = [
        "the",
        "for",
        "in",
        "with",
        "via",
        "on",
        "to",
        "without",
        "of",
        "through",
        "from",
        "by",
        "as",
        "a",
        "or",
        "at",
        "and",
        "an",
        "over",
        "new",
    ]

    if not title:
        errors.append("Rule has a missing 'title'.")

    if len(title) > 100:
        errors.append("Rule a title field with too many characters (>100)")

    if title.startswith("Detects "):
        errors.append("Rule has a title that starts with 'Detects'")
    if title.endswith("."):
        errors.append("Rule has a title that ends with '.'")

    wrong_casing = []
    for word in title.split(" "):
        if (
            word.islower()
            and not word.lower() in allowed_lowercase_words
            and not "." in word
            and not "/" in word
            and not word[0].isdigit()
        ):
            wrong_casing.append(word)
    if len(wrong_casing) > 0:
        errors.append(
            f"Rule has a title that has not title capitalization. Words: {wrong_casing}"
        )

    return errors


def test_falsepositives(falsepositives):
    errors = []
    banned_words = ["none", "pentest", "penetration test"]
    common_typos = ["unkown", "ligitimate", "legitim ", "legitimeate"]

    if falsepositives:
        for fp in falsepositives:
            # First letter should be capital
            try:
                if fp[0].upper() != fp[0]:
                    errors.append(
                        f"Rule defines a falsepositive item that does not start with a capital letter: {fp}."
                    )
            except TypeError as err:
                errors.append("The rule has an empty falsepositive item")

        for fp in falsepositives:
            for typo in common_typos:
                if fp == "Unknow" or typo in fp.lower():
                    errors.append(
                        f"The Rule defines a falsepositive with a common typo: {fp}."
                    )

            for banned_word in banned_words:
                if banned_word in fp.lower():
                    errors.append(
                        f"The rule defines a falsepositive with an invalid reason: {banned_word}."
                    )

    return errors


# Remove empty values from a nested dict - https://stackoverflow.com/questions/27973988/how-to-remove-all-empty-fields-in-a-nested-dict
# We need this to remove unnecessary logsource
def clean_empty(d):
    if isinstance(d, dict):
        return {k: v for k, v in ((k, clean_empty(v)) for k, v in d.items()) if v}
    if isinstance(d, list):
        return [v for v in map(clean_empty, d) if v]
    return d


class MyDumper(yaml.Dumper):
    def increase_indent(self, flow=False, indentless=False):
        return super(MyDumper, self).increase_indent(flow, False)


st.set_page_config(
    page_title="⚒️ SigmaHQ Rule Creation",
    layout="wide",
    initial_sidebar_state="expanded",
    page_icon=Image.open("streamlit/favicon.png"),
)
custom_css = """
    <style>
        body {
            background-color: #11252F;
        }
    </style>
    """

with open("streamlit/logsource_data.json", "r") as file:
    logsource_content = json.loads(file.read())

st.markdown(custom_css, unsafe_allow_html=True)
hide_streamlit_style = """
            <style>
            #MainMenu {visibility: hidden;}
            footer {visibility: hidden;}
            </style>
            """
st.markdown(hide_streamlit_style, unsafe_allow_html=True)

st.session_state["content_data"] = {
    "title": "Enter the title of the rule",
    "status": "Select the status of the rule",
    "description": "Enter a description for the rule",
    "references": ["Enter references"],
    "author": "Enter the author name",
    "date": "Enter the date of creation",
    "tags": ["Enter any relevant tags"],
    "logsource": {
        "product": "Enter the product name",
        "service": "Enter the service name",
        "category": "Enter the category name",
    },
    "detection": {"condition": "Enter the detection condition"},
    "falsepositives": ["Enter any known false positives"],
    "level": "Select the severity level",
}

if "file_loaded_manually" not in st.session_state:
    st.session_state["file_loaded_manually"] = False
st.title("⚒️ SigmaHQ Rule Creation")
st.header("Getting Started")
st.markdown(
    """
    If this is your first time writing a sigma rule. We highly recommend you check the following resources

    - 📚 [Writing You First Sigma Rule](https://sigmahq.io/docs/basics/rules.html)
    - 🧬 [What Are Value Modifiers?](https://sigmahq.io/docs/basics/modifiers.html)
    - 🔎 [Sigma Logsource](https://sigmahq.io/docs/basics/log-sources.html)
    - 🏷️ [Sigma Tags](https://github.com/SigmaHQ/sigma-specification/blob/main/Tags_specification.md)

    Make sure to follow the SigmaHQ conventions regarding the different fields for the best experience possible during the review process

    - [SigmaHQ Conventions](https://github.com/SigmaHQ/sigma-specification/blob/main/sigmahq/sigmahq_conventions.md)    
    - [SigmaHQ Rule Title Convention](https://github.com/SigmaHQ/sigma-specification/blob/main/sigmahq/sigmahq_title_rule.md)
    """
)

with st.sidebar:
    st.title("Content Settings")
    st.session_state["file_loaded_manually"] = False

    # Title
    st.session_state["content_data"]["title"] = st.text_input(
        "Title", st.session_state["content_data"]["title"]
    )

    # Status
    statuses = ["stable", "test", "experimental", "deprecated", "unsupported"]
    st.session_state["content_data"]["status"] = st.selectbox(
        "Status",
        statuses,
        index=statuses.index(st.session_state["content_data"]["status"])
        if st.session_state["content_data"]["status"] in statuses
        else 0,
    )

    # Description
    st.session_state["content_data"]["description"] = st.text_area(
        "Description", st.session_state["content_data"]["description"]
    )

    # References
    refs = st.text_area(
        "References (newline-separated)",
        "\n".join(st.session_state["content_data"]["references"]),
    )
    st.session_state["content_data"]["references"] = refs.split("\n")

    # Author
    st.session_state["content_data"]["author"] = st.text_input(
        "Author", st.session_state["content_data"]["author"]
    )

    # Date
    st.session_state["content_data"]["date"] = (
        st.date_input("Date", datetime.today())
    ).strftime("%Y/%m/%d")

    # Tags
    tags = st.text_area(
        "Tags (comma-separated)", ", ".join(st.session_state["content_data"]["tags"])
    )
    st.session_state["content_data"]["tags"] = tags.split(", ")

    # Logsource

    # Product
    products = [""] + logsource_content["product"]
    st.session_state["content_data"]["logsource"]["product"] = st.selectbox(
        "product",
        products,
        help="You can leave this field empty if its not required by your rule. It will automatically be removed during tha Yaml generation",
        index=products.index(st.session_state["content_data"]["logsource"]["product"])
        if st.session_state["content_data"]["logsource"]["product"] in products
        else 0,
    )
    # Service
    services = [""] + logsource_content["product"]
    st.session_state["content_data"]["logsource"]["service"] = st.selectbox(
        "service",
        services,
        help="You can leave this field empty if its not required by your rule. It will automatically be removed during tha Yaml generation",
        index=services.index(st.session_state["content_data"]["logsource"]["service"])
        if st.session_state["content_data"]["logsource"]["service"] in services
        else 0,
    )
    # Category
    categories = [""] + logsource_content["category"]
    st.session_state["content_data"]["logsource"]["category"] = st.selectbox(
        "category",
        categories,
        help="You can leave this field empty if its not required by your rule. It will automatically be removed during tha Yaml generation",
        index=categories.index(
            st.session_state["content_data"]["logsource"]["category"]
        )
        if st.session_state["content_data"]["logsource"]["category"] in categories
        else 0,
    )

    # Detection
    detection_str = yaml.dump(
        st.session_state["content_data"]["detection"], default_flow_style=False
    )
    st.session_state["content_data"]["detection"] = st.text_area(
        "Detection",
        detection_str,
        help="Example:\nselection_domain:\n    Contents|contains:\n        - '.githubusercontent.com'\n    selection_extension:\n        TargetFilename|contains:\n            - '.exe:Zone'\n    condition: all of selection*",
    )
    st.session_state["content_data"]["detection"] = yaml.safe_load(
        st.session_state["content_data"]["detection"]
    )

    # Falsepositives
    refs = st.text_area(
        "Falsepositives (newline-separated)",
        "\n".join(st.session_state["content_data"]["falsepositives"]),
    )
    st.session_state["content_data"]["falsepositives"] = refs.split("\n")

    # Level
    levels = ["informational", "low", "medium", "high", "critical"]
    st.session_state["content_data"]["level"] = st.selectbox(
        "Level",
        levels,
        index=levels.index(st.session_state["content_data"]["level"])
        if st.session_state["content_data"]["level"] in levels
        else 0,
    )

st.write("<h2>Sigma YAML Output</h2>", unsafe_allow_html=True)

st.session_state["content_data"] = clean_empty(st.session_state["content_data"])

# Just to make sure we don't dump unsafe code and at the same time enforce the indentation
yaml_output_tmp = yaml.safe_dump(
    st.session_state["content_data"],
    sort_keys=False,
    default_flow_style=False,
    indent=4,
)

yaml_output_tmp = yaml.safe_load(yaml_output_tmp)

yaml_output = yaml.dump(
    yaml_output_tmp,
    sort_keys=False,
    default_flow_style=False,
    Dumper=MyDumper,
    indent=4,
)

st.code(yaml_output)
if st.button("⚙️ Generate YAML File"):
    filename = "sigmahq_rule_" + str(uuid.uuid4()) + ".yml"
    st.success(f"{filename} Is Ready to Download!")
    st.info(
        f"Please don't forgot to follow the SigmaHQ file naming convention before contribution your rule https://github.com/SigmaHQ/sigma-specification/blob/main/sigmahq/Sigmahq_filename_rule.md"
    )
    download_button_str = st.download_button(
        label="Download YAML", data=yaml_output, file_name=filename, mime="text/yaml"
    )

    st.header("Contributing to SigmaHQ")
    st.markdown(
        """
        Congratulations! You've just generated a Sigma rule and you're only a few steps away from a great contribution. Please follow our [contribution guide](https://github.com/SigmaHQ/sigma/blob/master/CONTRIBUTING.md) to get started.
        """
    )

st.link_button(
    "⏳ Convert Using SigConverter",
    url="https://sigconverter.io",
)

if st.button("✔️ Validate Sigma Rule"):
    errors_num = 0

    # Title Test
    sigma_content = st.session_state["content_data"]
    title = sigma_content["title"]
    title_errors = test_title(title)
    if title_errors:
        errors_num += 1
        error_msg = ""
        for err in title_errors:
            error_msg += "- " + err + "\n"
        st.warning(
            f"""
            The rule has a non-conform 'title' field. Please check: https://github.com/SigmaHQ/sigma/wiki/Rule-Creation-Guide#title\n\n
            {error_msg}
            """
        )

    # False Positive Test
    sigma_content = st.session_state["content_data"]
    falsepositives = sigma_content["falsepositives"]
    falsepositives_errors = test_falsepositives(falsepositives)
    if falsepositives_errors:
        errors_num += 1
        error_msg = ""
        for err in falsepositives_errors:
            error_msg += "- " + err + "\n"
        st.warning(
            f"""
            The rule has a non-conform false positives section:\n\n
            {error_msg}
            """
        )

    # Logsource Test
    try:
        print(st.session_state)
        sigma_content = sigma_content["logsource"]
    except KeyError:
        errors_num += 1
        st.warning(
            "The rule has a missing 'logsource' field. Please check: https://sigmahq.io/docs/basics/log-sources.html"
        )

    if errors_num == 0:
        st.success("The tests have successfully passed")
