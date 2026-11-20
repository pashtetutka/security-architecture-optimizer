"""Streamlit UI for the current ETL catalog."""
from pathlib import Path

import streamlit as st

from siem.decision.ui import organizations_page


st.set_page_config(page_title='SIEM Decision Support', layout='wide')
st.title('Сопоставление источников с каталогом SIEM')
organizations_page(Path(__file__).resolve().parent)
