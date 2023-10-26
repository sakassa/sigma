import streamlit as st
import uuid
import yaml
import glob
import os

st.set_page_config(
    page_title="SigmaHQ Content Creation",
    layout="wide",
    initial_sidebar_state="expanded",
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
        "logsource": {
            "product": "Enter the product name",
            "service": "Enter the service name",
        },
        "detection": {"condition": "Enter the detection condition"},
        "status": "Select the status of the rule",
        "description": "Enter a description for the rule",
        "author": "Enter the author name",
        "references": ["Enter references"],
        "date": "Enter the date of creation",
        "modified": "Enter the date of modification",
        "fields": ["Enter any additional fields"],
        "falsepositives": ["Enter any known false positives"],
        "level": "Select the severity level",
        "tags": ["Enter any relevant tags"],
    }

st.title("SigmaHQ Content Creation")

with st.sidebar:
    st.title("Content Settings")

    # Create a dropdown menu with the file list
    selected_file = st.selectbox("Select a YAML file", file_list)

    # When a file is selected, read the file and update the session state
    if selected_file:
        with open(selected_file, "r") as file:
            file_content = yaml.safe_load(file)
            st.session_state["content_data"] = file_content
    st.text("or create new")
    # blank template
    if st.button("New"):
        st.session_state["content_data"] = {
            "title": "Enter the title of the rule",
            "logsource": {
                "product": "Enter the product name",
                "service": "Enter the service name",
            },
            "detection": {"condition": "Enter the detection condition"},
            "status": "Select the status of the rule",
            "description": "Enter a description for the rule",
            "author": "Enter the author name",
            "references": ["Enter references"],
            "date": "Enter the date of creation",
            "modified": "Enter the date of modification",
            "fields": ["Enter any additional fields"],
            "falsepositives": ["Enter any known false positives"],
            "level": "Select the severity level",
            "tags": ["Enter any relevant tags"],
        }

    st.session_state["content_data"]["title"] = st.text_input(
        "Title", st.session_state["content_data"]["title"]
    )
    st.session_state["content_data"]["logsource"]["product"] = st.text_input(
        "Log Source Product",
        st.session_state["content_data"]["logsource"].get("product", ""),
    )
    st.session_state["content_data"]["logsource"]["service"] = st.text_input(
        "Log Source Service",
        st.session_state["content_data"]["logsource"].get("service", ""),
    )
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

    statuses = ["stable", "test", "experimental", "deprecated", "unsupported"]
    st.session_state["content_data"]["status"] = st.selectbox(
        "Status",
        statuses,
        index=statuses.index(st.session_state["content_data"]["status"])
        if st.session_state["content_data"]["status"] in statuses
        else 0,
    )
    st.session_state["content_data"]["description"] = st.text_area(
        "Description", st.session_state["content_data"]["description"]
    )
    st.session_state["content_data"]["author"] = st.text_input(
        "Author", st.session_state["content_data"]["author"]
    )
    refs = st.text_area(
        "References (newline-separated)",
        "\n".join(st.session_state["content_data"]["references"]),
    )
    st.session_state["content_data"]["references"] = refs.split("\n")
    levels = ["informational", "low", "medium", "high", "critical"]
    st.session_state["content_data"]["level"] = st.selectbox(
        "Level",
        levels,
        index=levels.index(st.session_state["content_data"]["level"])
        if st.session_state["content_data"]["level"] in levels
        else 0,
    )
    tags = st.text_area(
        "Tags (comma-separated)", ", ".join(st.session_state["content_data"]["tags"])
    )
    st.session_state["content_data"]["tags"] = tags.split(", ")

st.write("<h2>Sigma YAML Output</h2>", unsafe_allow_html=True)

yaml_output = yaml.safe_dump(
    st.session_state["content_data"], sort_keys=False, default_flow_style=False
)
st.code(yaml_output)

if st.button("Generate YAML File"):
    filename = "SigmaHQ_Content_" + str(uuid.uuid4()) + ".yaml"
    with open(filename, "w") as file:
        file.write(yaml_output)
    st.success(f"File {filename} saved!")
