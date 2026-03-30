from reportlab.lib.pagesizes import A4
from reportlab.platypus import Paragraph, Spacer, Table
from reportlab.lib.styles import getSampleStyleSheet

def build_report(state, events):
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("<b>Post-Quantum Security Report</b>", styles["Title"]))
    elements.append(Spacer(1, 12))

    elements.append(Paragraph("<b>Runtime Cryptographic Posture</b>", styles["Heading2"]))
    elements.append(Spacer(1, 8))

    for k, v in state.items():
        elements.append(Paragraph(f"<b>{k}</b>: {v}", styles["Normal"]))

    elements.append(Spacer(1, 16))
    elements.append(Paragraph("<b>Security Test Case Results</b>", styles["Heading2"]))
    elements.append(Spacer(1, 8))

    table_data = [["Time", "Category", "Event", "Result", "Severity"]]
    for e in events:
        table_data.append([
            e["time"],
            e["category"],
            e["event"],
            e["result"],
            e.get("severity", "")
        ])

    table = Table(table_data, repeatRows=1)
    elements.append(table)

    return elements
