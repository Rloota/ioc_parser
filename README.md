# ioc-parser
IOC Parser is a tool to extract indicators of compromise from security reports in PDF format. A good collection of APT related reports with many IOCs can be found here: [APTNotes](https://github.com/kbandla/APTnotes).

## Usage
**iocp [-h] [-p INI] [-i FORMAT] [-o FORMAT] [-d] [-l LIB] FILE**
* *FILE* File/directory path to report(s)/Gmail account in double quotes ("username@gmail.com password")
* *-p INI* Pattern file
* *-i FORMAT* Input format (pdf/txt/docx/html/csv/xls/xlsx/gmail)
* *-o FORMAT* Output format (csv/json/yara/netflow/misp)
* *-d* Deduplicate matches
* *-l LIB* Parsing library
* *-e* MISP event ID


## Dependencies

* [docx2txt](http://docx2txt.sourceforge.net/)

## Requirements
One of the following PDF parsing libraries:
* [PyPDF2](https://github.com/mstamy2/PyPDF2) - *pip install pypdf2*
* [pdfminer](https://github.com/euske/pdfminer) - *pip install pdfminer*

For HTML parsing support:
* [BeautifulSoup](http://www.crummy.com/software/BeautifulSoup/) - *pip install beautifulsoup4*

For HTTP(S) support:
* [requests](http://docs.python-requests.org/en/latest/) - *pip install requests*

For XLS/XLSX support:
* [xlrd](https://github.com/python-excel/xlrd) - *pip install xlrd*

For Gmail support:
* [gmail](https://github.com/charlierguo/gmail)

For MISP output support:
* [PyMISP](https://github.com/MISP/PyMISP)

## Merged changes from forks:

[@buffer](https://github.com/buffer/ioc_parser/)

[@dadokkio](https://github.com/dadokkio/ioc_parser/)

[@LDO-CERT](https://github.com/LDO-CERT/ioc_parser/)

[@SteveClement](https://github.com/SteveClement/ioc_parser)
