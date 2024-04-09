import json
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

def generate_pdf(json_file_path,host):
    # Caminho para o arquivo PDF de saída
    pdf_file_path = f'cve_{host}_report.pdf'

    # Carregar dados JSON
    with open(json_file_path, 'r') as json_file:
        data = json.load(json_file)

    # Create PDF document with SimpleDocTemplate
    doc = SimpleDocTemplate(pdf_file_path, pagesize=letter)
    flowables = []
    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'title',
        parent=styles['Heading1'],
        alignment=1,
        textColor=colors.darkblue,
        spaceAfter=12,
    )

    heading_style = ParagraphStyle(
        'heading',
        parent=styles['Heading3'],
        spaceAfter=6,
        textColor=colors.darkblue,
    )

    body_style = styles['BodyText']
    body_style.spaceBefore = 0
    body_style.spaceAfter = 6

    # Function to add Paragraphs with custom styles
    def add_paragraph(text, style):
        paragraph = Paragraph(text, style)
        flowables.append(paragraph)

    # Function to convert boolean flag to human-readable string
    def bool_to_string(flag):
        return "Yes" if flag else "No"

    # Add a logo at the top (if you have a logo)
    # logo = "path_to_logo.jpg"
    # flowables.append(Image(logo, width=2*inch, height=1*inch))
    # flowables.append(Spacer(1, 0.25*inch))

    # Gerar conteúdo do PDF
    for category, cve_list in data.items():
        add_paragraph(f'Service: {category}', title_style)
        if not cve_list:
            add_paragraph("No CVEs associated with this service.", body_style)
        else:
            for cve in cve_list:
                add_paragraph(f'CVE ID: {cve["cveId"]}', heading_style)
                add_paragraph(f'Publish Date: {cve["publishDate"]}', body_style)
                add_paragraph(f'Exploit Exists: {bool_to_string(cve["exploitExists"])}', body_style)
                add_paragraph(f'Summary: {cve["summary"]}', body_style)
                add_paragraph(f'CVSS Severity: {cve["cvss_details"][0]["baseSeverity"]}', body_style)
                add_paragraph(f'Attack Vector: {cve["cvss_details"][0]["cvssVector"]}', body_style)
                add_paragraph(f'EPSS Score: {cve["epssScore"]})', body_style)
                add_paragraph(f'Overflow: {bool_to_string(cve["isOverflow"])}', body_style)
                add_paragraph(f'Code Execution: {bool_to_string(cve["isCodeExecution"])}', body_style)
                add_paragraph(f'Denial of Service: {bool_to_string(cve["isDenialOfService"])}', body_style)
                add_paragraph(f'Memory Corruption: {bool_to_string(cve["isMemoryCorruption"])}', body_style)
                add_paragraph(f'Sql Injection: {bool_to_string(cve["isSqlInjection"])}', body_style)
                add_paragraph(f'Xss: {bool_to_string(cve["isXss"])}', body_style)
                add_paragraph(f'Directory Traversal: {bool_to_string(cve["isDirectoryTraversal"])}', body_style)
                add_paragraph(f'File Inclusion: {bool_to_string(cve["isFileInclusion"])}', body_style)
                add_paragraph(f'Csrf: {bool_to_string(cve["isCsrf"])}', body_style)
                add_paragraph(f'Xxe: {bool_to_string(cve["isXxe"])}', body_style)
                add_paragraph(f'Ssrf: {bool_to_string(cve["isSsrf"])}', body_style)
                add_paragraph(f'Open Redirect: {bool_to_string(cve["isOpenRedirect"])}', body_style)
                add_paragraph(f'Input Validation: {bool_to_string(cve["isInputValidation"])}', body_style)
                add_paragraph(f'Bypass Something: {bool_to_string(cve["isBypassSomething"])}', body_style)
                add_paragraph(f'Gain Privilege: {bool_to_string(cve["isGainPrivilege"])}', body_style)
                add_paragraph(f'Information Leak: {bool_to_string(cve["isInformationLeak"])}', body_style)

                # ... (add other 'is' flags as needed)
                flowables.append(Spacer(1, 0.1*inch))  # Small space after each entry
        flowables.append(PageBreak())  # New page for each category

    # Build the document
    doc.build(flowables)

    print(f'PDF generated successfully at {pdf_file_path}')