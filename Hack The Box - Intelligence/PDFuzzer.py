# PDFuzzer by H4RR1ZN
# HTB - Intelligence
# install requirements with pip install -r requirements.txt
#


import requests
import itertools
import os
from concurrent.futures import ThreadPoolExecutor
import PyPDF2
from pwn import *

base_url = "http://intelligence.htb/documents/"
year = "2020"

meses = ["{:02d}".format(m) for m in range(1, 13)]
dias = ["{:02d}".format(d) for d in range(1, 32)]
fechas = itertools.product(meses, dias)

total_documentos = 0
output_folder = "./documentos"

if not os.path.exists(output_folder):
    os.makedirs(output_folder)

resultados = {}

def procesar_documento(url):
    global total_documentos
    try:
        response = requests.get(url)
        if response.status_code == 200:
            filename = url.split("/")[-1]
            filepath = os.path.join(output_folder, filename)
            with open(filepath, "wb") as file:
                file.write(response.content)
            total_documentos += 1
            log.success(f"Documento descargado y almacenado: {filename}")

            palabras_clave = buscar_palabras_clave(filepath)
            if palabras_clave:
                resultados[filename] = palabras_clave
    except Exception as e:
        log.fail(f"Error al procesar documento {url}: {e}")

def buscar_palabras_clave(filepath):
    palabras_clave = ["password", "account", "user"]
    resultados_palabras_clave = {}
    try:
        with open(filepath, "rb") as file:
            pdf_reader = PyPDF2.PdfFileReader(file)
            num_pages = pdf_reader.numPages
            for page_num in range(num_pages):
                page = pdf_reader.getPage(page_num)
                text = page.extract_text()
                for palabra_clave in palabras_clave:
                    if palabra_clave in text and palabra_clave not in resultados_palabras_clave:
                        if filepath not in resultados_palabras_clave:
                            resultados_palabras_clave[filepath] = ""
                        resultados_palabras_clave[filepath] += text
    except Exception as e:
        log.fail(f"Error al buscar palabras clave en {filepath}: {e}")
    return resultados_palabras_clave

with ThreadPoolExecutor() as executor:
    for mes, dia in fechas:
        fecha = f"{year}-{mes}-{dia}"
        url = f"{base_url}{fecha}-upload.pdf"

        executor.submit(procesar_documento, url)
print("\n")
log.warning(f"Total de documentos encontrados: {total_documentos}")

print("\n--- Informe de Palabras Clave ---")
for documento, texto in resultados.items():
    print(f"\nDocumento: {documento}")
    print("\nTexto relacionado:")
    for key, value in texto.items():
        #print(f"{key}:")
        words = value.split()
        unique_words = set()
        unique_text = ""
        for word in words:
            if word.lower() not in unique_words:
                unique_words.add(word.lower())
                unique_text += word + " "
        log.warning(unique_text)
