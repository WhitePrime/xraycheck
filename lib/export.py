#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Модуль экспорта результатов в различные форматы.
"""

import csv
import json
from datetime import datetime
from pathlib import Path


def export_to_json(results: list, metrics: dict, output_path: str) -> str:
    """Экспорт результатов в JSON."""
    data = {
        'timestamp': datetime.now().isoformat(),
        'total': len(results),
        'available': sum(1 for r in results if isinstance(r, dict) and r.get('available', False) or isinstance(r, str)),
        'results': results,
        'metrics': metrics
    }
    json_path = output_path.replace('.txt', '.json')
    Path(json_path).parent.mkdir(parents=True, exist_ok=True)
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return json_path


def export_to_csv(results: list, output_path: str) -> str:
    """Экспорт результатов в CSV."""
    csv_path = output_path.replace('.txt', '.csv')
    Path(csv_path).parent.mkdir(parents=True, exist_ok=True)
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=[
            'key', 'available', 'avg_response_time', 'geolocation', 'error'
        ])
        writer.writeheader()
        for result in results:
            if isinstance(result, dict):
                writer.writerow({
                    'key': result.get('key', ''),
                    'available': result.get('available', False),
                    'avg_response_time': result.get('avg_response_time', ''),
                    'geolocation': result.get('geolocation', {}).get('country', '') if isinstance(result.get('geolocation'), dict) else '',
                    'error': str(result.get('error', ''))
                })
            elif isinstance(result, str):
                writer.writerow({
                    'key': result,
                    'available': True,
                    'avg_response_time': '',
                    'geolocation': '',
                    'error': ''
                })
    return csv_path


def export_to_html(results: list, metrics: dict, output_path: str) -> str:
    """Экспорт результатов в HTML."""
    html_path = output_path.replace('.txt', '.html')
    Path(html_path).parent.mkdir(parents=True, exist_ok=True)
    total = len(results)
    available = sum(1 for r in results if isinstance(r, str) or (isinstance(r, dict) and r.get('available', False)))
    
    rows_html = ""
    for i, result in enumerate(results, 1):
        if isinstance(result, str):
            key = result
            status = "✓ Рабочий"
            status_class = "available"
            time_str = ""
            geo = ""
        else:
            key = result.get('key', '')
            status = "✓ Рабочий" if result.get('available', False) else "✗ Не рабочий"
            status_class = "available" if result.get('available', False) else "unavailable"
            time_str = f"{result.get('avg_response_time', 0):.2f}с" if result.get('avg_response_time') else ""
            geo = result.get('geolocation', {}).get('country', '') if isinstance(result.get('geolocation'), dict) else ""
        
        rows_html += f"""
            <tr>
                <td>{i}</td>
                <td><code style="word-break: break-all;">{key[:100]}...</code></td>
                <td class="{status_class}">{status}</td>
                <td>{time_str}</td>
                <td>{geo}</td>
            </tr>
        """
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Результаты проверки VLESS-ключей</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
            h1 {{ color: #333; }}
            .summary {{ background-color: white; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
            table {{ border-collapse: collapse; width: 100%; background-color: white; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #4CAF50; color: white; }}
            tr:nth-child(even) {{ background-color: #f2f2f2; }}
            .available {{ color: green; font-weight: bold; }}
            .unavailable {{ color: red; font-weight: bold; }}
            code {{ background-color: #f4f4f4; padding: 2px 4px; border-radius: 3px; }}
        </style>
    </head>
    <body>
        <h1>Результаты проверки VLESS-ключей</h1>
        <div class="summary">
            <p><strong>Проверено:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Всего:</strong> {total}, <strong>Рабочих:</strong> <span class="available">{available}</span>, <strong>Не рабочих:</strong> <span class="unavailable">{total - available}</span></p>
            <p><strong>Успешность:</strong> {(available/total*100 if total > 0 else 0):.1f}%</p>
        </div>
        <table>
            <tr>
                <th>№</th>
                <th>Ключ</th>
                <th>Статус</th>
                <th>Время ответа</th>
                <th>Геолокация</th>
            </tr>
            {rows_html}
        </table>
    </body>
    </html>
    """
    
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    return html_path
