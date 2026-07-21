# Wazuh Journal

A source-available SOC interface for viewing live Wazuh alerts and analyzing selected events through an OpenAI-compatible API. The interface is available in English by default and can be switched to Russian.

Русская версия интерфейса включается переключателем `EN / RU`.

## Требования

- Node.js `>=22.13.0`
- npm

## Локальный запуск

```bash
npm install
cp .env.example .env.local
npm run dev
```

После запуска откройте локальный адрес, показанный в терминале. Проект не требует облачной базы данных или внешнего хостинга.

Без переменных `OPENAI_*` анализ отключён и интерфейс показывает ошибку настройки. Секреты хранятся только в `.env.local`; этот файл не следует добавлять в Git.

Для production задайте все необходимые переменные в секретах среды выполнения. Минимально необходимы `AUTH_SESSION_SECRET` и параметры доступной Wazuh-интеграции; без них приложение явно покажет ошибку подключения и не подставит демонстрационные события.

## Развёртывание

Проект рассчитан на Node.js `>=22.13.0` и стандартный npm-процесс:

```bash
npm ci
npm run build
npm start
```

Перед публикацией выполните `npm run lint` и `npm test`. Для Cloudflare Sites сохраните `.openai/hosting.json` и задайте переменные окружения в настройках runtime, а не в Git.

## Проверка

```bash
npm run build
npm run lint
```

## Переменные окружения

- `OPENAI_BASE_URL`, `OPENAI_API_KEY`, `OPENAI_MODEL` — необязательный AI-анализ.
- `WAZUH_SSH_HOST`, `WAZUH_SSH_PORT`, `WAZUH_SSH_USER`, `WAZUH_SSH_PRIVATE_KEY` — будущий локальный server-side bridge к Wazuh.
- `AD_TENANT_ID`, `AD_CLIENT_ID`, `AD_CLIENT_SECRET` — будущая серверная авторизация Active Directory.

Приложение не генерирует и не подставляет тестовые события. При недоступности интеграции отображается явная ошибка. Один запрос анализа всегда содержит только один выбранный алерт.

## License

Source code is available for personal, educational, research, and other non-commercial use under the custom [Wazuh Journal Non-Commercial License](LICENSE). Commercial use requires a separate written license from the copyright holder.
