"""Fill the title page of Work1_Report.docx (variant, name, student id, date)."""

import shutil

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Pt

DOCX = r"D:\hdu-work1\docs\Work1_Report.docx"
ROOT_COPY = r"D:\[HDU-CS4-26-27-1] Information Security\work1\Work1_Report.docx"

VALUES = {
    0: "CVE-2014-3120",     # Variant No.  (= the CVE id)
    1: "mahaotian",         # Student
    2: "23320311",          # HDU number
    4: "22 / 10 / 2026",    # Date
}


def main():
    doc = Document(DOCX)
    table = doc.tables[0]
    for row_index, value in VALUES.items():
        cell = table.cell(row_index, 1)
        for paragraph in cell.paragraphs:
            for run in list(paragraph.runs):
                run._element.getparent().remove(run._element)
        paragraph = cell.paragraphs[0]
        paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = paragraph.add_run(value)
        run.font.name = "Times New Roman"
        run.font.size = Pt(11)

    doc.save(DOCX)
    shutil.copyfile(DOCX, ROOT_COPY)
    print("title page updated ->", DOCX)
    print("copied ->", ROOT_COPY)


if __name__ == "__main__":
    main()
