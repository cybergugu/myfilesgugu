import json
import time
import sys
from pathlib import Path
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager

# Установка: pip install ipwhois dnspython
try:
    from ipwhois import IPWhois
    import dns.resolver
except ImportError:
    print("Предупреждение: библиотеки ipwhois/dnspython не найдены.")
    print("Для анализа подсетей установите: pip install ipwhois dnspython")
    IPWhois = None
    dns = None

def get_chrome_options():
    options = Options()
    options.set_capability('goog:loggingPrefs', {'performance': 'ALL'})
    options.add_argument('--headless=new')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--window-size=1920,1080')
    options.add_argument('--log-level=3')
    prefs = {"profile.managed_default_content_settings.images": 2}
    options.add_experimental_option("prefs", prefs)
    return options

def get_domains_with_selenium(url: str) -> list:
    """Собирает все домены со страницы через Selenium"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    print(f"[*] Анализируем сайт через Selenium: {url}")
    
    try:
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=get_chrome_options())
    except Exception as e:
        print(f"[Ошибка запуска] {e}")
        return []

    unique_domains = set()
    
    try:
        driver.get(url)
        
        try:
            WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
        except:
            print("[!] Таймаут загрузки страницы")

        # Скроллинг для загрузки контента
        last_height = driver.execute_script("return document.body.scrollHeight")
        for _ in range(3):
            driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
            time.sleep(1.5)
            new_height = driver.execute_script("return document.body.scrollHeight")
            if new_height == last_height:
                break
            last_height = new_height

        # Сбор логов
        logs = driver.get_log('performance')
        target_domain = urlparse(url).netloc

        for entry in logs:
            message = json.loads(entry['message'])['message']
            if message['method'] == 'Network.requestWillBeSent':
                request_url = message['params']['request']['url']
                if request_url.startswith('http'):
                    parsed = urlparse(request_url)
                    domain = parsed.netloc.split(':')[0]
                    if domain:
                        unique_domains.add(domain)
        
        print(f"[✓] Найдено уникальных доменов: {len(unique_domains)}")

    except Exception as e:
        print(f"[!] Ошибка во время выполнения: {e}")
    finally:
        driver.quit()

    return sorted(list(unique_domains))

def get_ip_info(ip_addr: str):
    """Определяет подсеть и ASN для IP-адреса"""
    if not IPWhois:
        return None
    
    try:
        obj = IPWhois(ip_addr)
        res = obj.lookup_rdap(depth=1)
        
        network = res.get('network', {})
        cidr = network.get('cidr', 'Не определено')
        name = network.get('name', 'Нет данных')
        
        asn = res.get('asn', 'Unknown')
        asn_desc = res.get('asn_description', 'Нет описания')
        asn_country = res.get('asn_country_code', '')
        
        return {
            'ip': ip_addr,
            'cidr': cidr,
            'network_name': name,
            'asn': asn,
            'asn_desc': asn_desc,
            'country': asn_country
        }
    except Exception as e:
        return None

def resolve_domains_to_subnets(domains: list) -> dict:
    """Резолвит список доменов в подсети"""
    if not dns or not IPWhois:
        print("[!] Анализ подсетей недоступен (нет ipwhois/dnspython)")
        return {}
    
    print(f"\n[*] Начинаем резолвацию {len(domains)} доменов...")
    
    subnet_results = {}
    processed_ips = set()
    
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']
    resolver.timeout = 3
    resolver.lifetime = 3
    
    for i, domain in enumerate(domains, 1):
        print(f"\r[*] Обработка {i}/{len(domains)}: {domain[:40]}...", end='')
        
        try:
            answers = resolver.resolve(domain, 'A')
            
            for rdata in answers:
                ip = str(rdata)
                
                # Пропускаем виртуальные IP от VPN
                if ip.startswith('198.18.') or ip.startswith('198.19.'):
                    continue
                
                # Пропускаем уже обработанные IP
                if ip in processed_ips:
                    continue
                
                processed_ips.add(ip)
                
                # Получаем информацию о подсети
                info = get_ip_info(ip)
                if not info:
                    continue
                
                cidr = info['cidr']
                
                if cidr not in subnet_results:
                    subnet_results[cidr] = {
                        'network_name': info['network_name'],
                        'asn': info['asn'],
                        'asn_desc': info['asn_desc'],
                        'country': info['country'],
                        'ips': [],
                        'domains': set()
                    }
                
                subnet_results[cidr]['ips'].append(ip)
                subnet_results[cidr]['domains'].add(domain)
                
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            pass
        except Exception:
            pass
    
    print(f"\n[✓] Найдено уникальных подсетей: {len(subnet_results)}")
    return subnet_results

def save_combined_result(site_url: str, domains: list, subnets: dict):
    """Сохраняет домены и подсети в один файл"""
    parsed_url = urlparse(site_url if site_url.startswith('http') else 'https://' + site_url)
    clean_name = parsed_url.netloc.replace('.', '_')
    filename = f"analysis_{clean_name}.txt"
    file_path = Path(__file__).parent / filename

    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(f"Источник: {site_url}\n")
            f.write(f"Всего доменов: {len(domains)}\n")
            f.write(f"Всего подсетей: {len(subnets)}\n")
            f.write("="*60 + "\n\n")
            
            # РАЗДЕЛ 1: ПОДСЕТИ
            f.write("РАЗДЕЛ 1: ПОДСЕТИ (CIDR)\n")
            f.write("="*60 + "\n")
            if subnets:
                for cidr in sorted(subnets.keys()):
                    f.write(f"{cidr}\n")
            else:
                f.write("(анализ подсетей не выполнен)\n")
            
            f.write("\n")
            
            # РАЗДЕЛ 2: ДОМЕНЫ
            f.write("РАЗДЕЛ 2: ДОМЕНЫ\n")
            f.write("="*60 + "\n")
            for domain in domains:
                f.write(f"{domain}\n")
            
            f.write("\n")
            
            # РАЗДЕЛ 3: ДЕТАЛЬНАЯ ИНФОРМАЦИЯ О ПОДСЕТЯХ
            if subnets:
                f.write("РАЗДЕЛ 3: ДЕТАЛЬНАЯ ИНФОРМАЦИЯ О ПОДСЕТЯХ\n")
                f.write("="*60 + "\n\n")
                
                total_ips = sum(len(info['ips']) for info in subnets.values())
                f.write(f"Всего найдено IP: {total_ips}\n")
                f.write(f"Уникальных подсетей: {len(subnets)}\n")
                f.write("-"*60 + "\n\n")
                
                for cidr, info in sorted(subnets.items()):
                    f.write(f"Подсеть (CIDR): {cidr}\n")
                    
                    if info['asn']:
                        f.write(f"ASN: AS{info['asn']}\n")
                        
                    if info['asn_desc']:
                        f.write(f"Провайдер: {info['asn_desc']}\n")
                        
                    if info['country']:
                        f.write(f"Страна: {info['country']}\n")
                    
                    f.write(f"IP-адреса ({len(info['ips'])}): {', '.join(sorted(info['ips']))}\n")
                    f.write(f"Связанные домены ({len(info['domains'])}): {', '.join(sorted(list(info['domains'])[:5]))}")
                    if len(info['domains']) > 5:
                        f.write(f" ... и еще {len(info['domains'])-5}")
                    f.write("\n")
                    f.write("-" * 60 + "\n\n")
                
        return file_path
    except IOError as e:
        print(f"[!] Ошибка записи файла: {e}")
        return None

if __name__ == "__main__":
    try:
        target = input("Введите сайт (например youtube.com): ").strip()
        
        if not target:
            print("[!] Сайт не введен.")
            sys.exit(1)
        
        # Шаг 1: Собираем домены через Selenium
        found_domains = get_domains_with_selenium(target)
        
        if not found_domains:
            print("[!] Домены не найдены.")
            sys.exit(1)
        
        # Шаг 2: Анализируем подсети для найденных доменов
        subnets = {}
        if IPWhois and dns:
            analyze = input("\nАнализировать подсети для найденных доменов? (y/n): ").strip().lower()
            if analyze == 'y':
                subnets = resolve_domains_to_subnets(found_domains)
        
        # Шаг 3: Сохраняем результаты
        saved_path = save_combined_result(target, found_domains, subnets)
        
        print("\n" + "="*60)
        print(f"✓ Найдено доменов: {len(found_domains)}")
        if subnets:
            print(f"✓ Найдено подсетей: {len(subnets)}")
        
        if saved_path:
            print(f"✓ Файл сохранен: {saved_path.name}")
            print(f"  Полный путь: {saved_path}")
        print("="*60)
            
    except KeyboardInterrupt:
        print("\n[!] Программа остановлена пользователем.")
    except Exception as e:
        print(f"\n[!] Критическая ошибка: {e}")
