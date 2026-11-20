import sys

from pypdf import PdfReader


def main(path: str) -> None:
    reader = PdfReader(path)
    for page in reader.pages:
        print(page.extract_text())


if __name__ == '__main__':
    main(sys.argv[1])
