# Consul Viewer TUI

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version 1.0.0](https://img.shields.io/badge/version-1.0.0-blue.svg)](./CHANGELOG.md)

![consul-viewer screenshot](images/consul-viewer1.png)
![consul-viewer screenshot](images/consul-viewer2.png)

`Consul Viewer TUI` — это keyboard-first TUI-приложение для read-only просмотра Consul.

Приложение реализовано в одном Python-файле и предназначено для диагностики и наблюдения без изменения данных Consul.

## Возможности

- Только read-only доступ к данным Consul
- `Dashboard` со сводкой по кластеру и локальному агенту
- `Telemetry` на основе метрик агента в формате Prometheus
- `Services` и инстансы сервисов
- `Nodes` и инстансы на нодах
- KV browser с preview и полным viewer
- Список сессий и детали
- ACL-разделы:
  - `Tokens`
  - `Policies`
  - `Roles`
  - `Auth`
- Многоуровневая фильтрация:
  - текстовый фильтр
  - status filter
  - структурный instance filter по тегам и metadata
- Сортировка для каждого вида списка
- Фоновая загрузка, TTL-кэш, обработка stale state

## Требования

- Python 3.9+
- `urwid`

## Установка

Установите единственную внешнюю зависимость:

```bash
pip install urwid
```

## Запуск

Базовый запуск:

```bash
python consul-viewer.py
```

Примеры:

```bash
python consul-viewer.py --addr http://127.0.0.1:8500
python consul-viewer.py --addr https://consul.example.org:8501 --token <TOKEN>
python consul-viewer.py --refresh 10 --timeout 15
```

Поддерживаемые параметры CLI:

- `--addr`
- `--token`
- `--refresh`
- `--timeout`
- `--insecure`
- `--dc`
- `--ca-file`
- `--cert-file`
- `--key-file`

Поддерживаемые переменные окружения:

- `CONSUL_HTTP_ADDR`
- `CONSUL_HTTP_TOKEN`

## Основные клавиши

- `Tab` / `Shift+Tab` / `Ctrl+Tab` — переключение между разделами
- `Left` / `Right` — переключение между `Items` и `Details`
- `Enter` — drill-down в выбранный объект
- `Backspace` — возврат назад
- `F1` — help
- `F3` — полный viewer
- `F4` — показать `SecretID` токена
- `F5` — обновить текущий раздел
- `F6` — status filter
- `F7` или `/` — текстовый фильтр
- `F8` — выбор, какие фильтры сбрасывать
- `F9` — структурный фильтр инстансов
- `F11` — сортировка
- `F10` / `Esc` — подтверждение выхода

## Важные файлы

- `consul-viewer.py` — основное приложение
- `UserGuide.md` — подробная инструкция пользователя на английском языке
- `UserGuide-ru.md` — подробная инструкция пользователя
- `plan.md` — актуальный план и трекер реализации
- `diagramms/` — PlantUML-диаграммы архитектуры

## Замечания

- Приложение изначально спроектировано как read-only.
- Функциональность `Mesh` пока не реализована.
- Часть статусов здоровья и telemetry-индикаторов рассчитывается эвристически.

## Author

**Tarasov Dmitry**
- Email: dtarasov7@gmail.com

## Attribution
Parts of this code were generated with assistance
