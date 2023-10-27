import streamlit as st
import uuid
import yaml
import glob
import json


class MyDumper(yaml.Dumper):
    def increase_indent(self, flow=False, indentless=False):
        return super(MyDumper, self).increase_indent(flow, False)


st.set_page_config(
    page_title="⚒️ SigmaHQ Rule Creation",
    layout="wide",
    initial_sidebar_state="expanded",
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
    "modified": "Enter the date of modification",
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

    # Tags
    tags = st.text_area(
        "Tags (comma-separated)", ", ".join(st.session_state["content_data"]["tags"])
    )
    st.session_state["content_data"]["tags"] = tags.split(", ")

    # Logsource

    # Product
    products = logsource_content["product"]
    st.session_state["content_data"]["logsource"]["product"] = st.selectbox(
        "product",
        products,
        index=products.index(st.session_state["content_data"]["logsource"]["product"])
        if st.session_state["content_data"]["logsource"]["product"] in products
        else 0,
    )
    # Service
    services = logsource_content["product"]
    st.session_state["content_data"]["logsource"]["service"] = st.selectbox(
        "service",
        services,
        index=services.index(st.session_state["content_data"]["logsource"]["service"])
        if st.session_state["content_data"]["logsource"]["service"] in services
        else 0,
    )
    # Category
    categories = logsource_content["category"]
    st.session_state["content_data"]["logsource"]["category"] = st.selectbox(
        "category",
        categories,
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
        help="Enter the detection condition. Example:\nselection_domain:\n    Contents|contains:\n        - '.githubusercontent.com'\n    selection_extension:\n        TargetFilename|contains:\n            - '.exe:Zone'\n    condition: all of selection*",
    )
    st.session_state["content_data"]["detection"] = yaml.safe_load(
        st.session_state["content_data"]["detection"]
    )

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
if st.button("Generate YAML File"):
    filename = "sigmahq_rule_" + str(uuid.uuid4()) + ".yml"
    st.success(f"File {filename} Is Ready to Download!")
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
