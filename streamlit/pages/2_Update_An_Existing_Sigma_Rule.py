from datetime import datetime
import streamlit as st
import uuid
import yaml
import glob
import os
import ntpath
import json
from PIL import Image


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
    page_title="🧰 SigmaHQ Rule Update",
    layout="wide",
    initial_sidebar_state="expanded",
    page_icon=Image.open("streamlit/favicon.png"),
)

custom_css = """
    <style>
        body {
            background-color: #10252F;
        }
    </style>
    """

st.markdown(custom_css, unsafe_allow_html=True)

file_list = (
    glob.glob("rules/**/*.yml", recursive=True)
    + glob.glob("rules/**/*.yaml", recursive=True)
    + glob.glob("rules-*/**/*.yml", recursive=True)
    + glob.glob("rules-*/**/*.yaml", recursive=True)
)

with open("streamlit/logsource_data.json", "r") as file:
    logsource_content = json.loads(file.read())

hide_streamlit_style = """
            <style>
            #MainMenu {visibility: hidden;}
            footer {visibility: hidden;}
            </style>
            """
st.markdown(hide_streamlit_style, unsafe_allow_html=True)

if "content_data" not in st.session_state:
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

st.title("🧰 SigmaHQ Rule Update")
print("Current Working Directory:", os.getcwd())

with st.sidebar:
    st.title("Content Settings")

    # Create a dropdown menu with the file list
    selected_file = st.selectbox("Select a YAML file", file_list)

    # When a file is selected, read the file and update the session state
    if selected_file:
        with open(selected_file, "r") as file:
            file_content = yaml.safe_load(file)
            st.session_state["content_data"] = file_content

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

    # Modified
    st.session_state["content_data"]["modified"] = (
        st.date_input("Modified", datetime.today())
    ).strftime("%Y/%m/%d")

    # Tags
    tags = st.text_area(
        "Tags (comma-separated)", ", ".join(st.session_state["content_data"]["tags"])
    )
    st.session_state["content_data"]["tags"] = tags.split(", ")

    # Logsource

    # Product
    try:
        products = logsource_content["product"]
        st.session_state["content_data"]["logsource"]["product"] = st.selectbox(
            "product",
            products,
            index=products.index(
                st.session_state["content_data"]["logsource"]["product"]
            )
            if st.session_state["content_data"]["logsource"]["product"] in products
            else 0,
        )
    except:
        pass
    # Service
    try:
        services = logsource_content["product"]
        st.session_state["content_data"]["logsource"]["service"] = st.selectbox(
            "service",
            services,
            index=services.index(
                st.session_state["content_data"]["logsource"]["service"]
            )
            if st.session_state["content_data"]["logsource"]["service"] in services
            else 0,
        )
    except:
        pass
    # Category
    try:
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
    except:
        pass

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
    width=1000,
)
yaml_output_tmp = yaml.safe_load(yaml_output_tmp)
yaml_output = yaml.dump(
    yaml_output_tmp,
    sort_keys=False,
    default_flow_style=False,
    Dumper=MyDumper,
    indent=4,
    width=1000,
)

st.code(yaml_output)

if st.button("⚙️ Generate YAML File"):
    filename = ntpath.basename(selected_file)
    st.success(f"{filename} Ready to download!")
    download_button_str = st.download_button(
        label="Download YAML",
        data=yaml_output,
        file_name=filename,
        mime="text/yaml",
    )

    st.header("Contributing to SigmaHQ")
    st.markdown(
        """
        Congratulations! You've just updated the Sigma rule and you're only a few steps away from a great contribution. Please follow our [contribution guide](https://github.com/SigmaHQ/sigma/blob/master/CONTRIBUTING.md) to get started.
        """
    )

st.link_button(
    "⏳ Convert Using SigConverter",
    url="https://sigconverter.io",
)

if st.button("✔️ Validate Sigma Rule"):
    sigma_content = st.session_state["content_data"]
    title = sigma_content["title"].istitle()

    if not title:
        st.warning("The rule title isn't using title casing")
