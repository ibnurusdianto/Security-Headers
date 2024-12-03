import requests
from rich.console import Console
from rich.table import Table
from rich import print
from rich.panel import Panel
from rich.text import Text
from pyfiglet import figlet_format

console = Console()

author = "buble"
tool_info = "Program ini digunakan untuk menganalisis security headers pada aplikasi web."
how_to_use = "Cara menggunakan:\n1. Jalankan program ini.\n2. Masukkan URL target yang ingin dianalisis.\n3. Program akan menampilkan security headers dan statusnya."

def analyze_security_headers(url):
    try:
        response = requests.get(url)
        headers = response.headers

        # list security headers
        security_headers = {
            "Content-Security-Policy": headers.get("Content-Security-Policy"),
            "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options"),
            "X-Frame-Options": headers.get("X-Frame-Options"),
            "X-XSS-Protection": headers.get("X-XSS-Protection"),
            "Referrer-Policy": headers.get("Referrer-Policy"),
            "Feature-Policy": headers.get("Feature-Policy"),
            "Permissions-Policy": headers.get("Permissions-Policy"),
            "Public-Key-Pins": headers.get("Public-Key-Pins"),
            "Expect-CT": headers.get("Expect-CT"),
        }

        return security_headers
    except requests.exceptions.RequestException as e:
        console.print(f"[red]Error: {e}[/red]")
        return None


# tampilan hasil
def display_results(security_headers):
    console.print("\n[bold cyan]Hasil Analisis Security Headers:[/bold cyan]")
    table = Table(title="Security Headers Analysis", title_justify="left")
    table.add_column("Header", justify="left", style="cyan", no_wrap=True)
    table.add_column("Value", justify="left", style="magenta", no_wrap=True)
    table.add_column("Status", justify="left", style="green", no_wrap=True)

    for header, value in security_headers.items():
        if value is None:
            status = "[red]Missing[/red]"
        else:
            status = "[green]Present[/green]"
            if header == "Content-Security-Policy" and "unsafe-inline" in value:
                status = "[yellow]Weak (unsafe-inline detected)[/yellow]"
            elif header == "Strict-Transport-Security" and "max-age=0" in value:
                status = "[yellow]Weak (max-age=0 detected)[/yellow]"
            elif header == "X-XSS-Protection" and value != "1; mode=block":
                status = "[yellow]Weak (not set to block)[/yellow]"

        table.add_row(header, str(value) if value else "N/A", status)

    console.print(table)

def main():
    console.print(Panel(Text(figlet_format("Security Headers Analyzer", font="slant"), style="bold cyan"), title="Tool Name"))
    console.print(Panel(Text(f"Penulis: {author}\n\n{tool_info}\n\n{how_to_use}", style="bold green"), title="Informasi Tool"))

    url = input("Masukkan URL target (contoh: https://example.com): ")
    security_headers = analyze_security_headers(url)

    if security_headers:
        display_results(security_headers)

if __name__ == "__main__":
    main()
