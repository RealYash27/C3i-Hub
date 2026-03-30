import json
import os
from reportlab.platypus import SimpleDocTemplate
from reportlab.lib.pagesizes import A4

from dashboard.report_template import build_report

BASE_DIR = os.path.dirname(__file__)
STATE_FILE = os.path.join(BASE_DIR, "runtime_state.json")
EVENTS_FILE = os.path.join(BASE_DIR, "events.json")


def export_pdf(output="PostQuantum_Security_Report.pdf"):
    try:
        with open(STATE_FILE) as f:
            state = json.load(f)
        with open(EVENTS_FILE) as f:
            events = json.load(f)

        doc = SimpleDocTemplate(output, pagesize=A4)
        elements = build_report(state, events)
        doc.build(elements)

        print(f"[+] PDF report generated: {output}")

    except Exception as e:
        print("PDF export failed:", e)


if __name__ == "__main__":
    export_pdf()
