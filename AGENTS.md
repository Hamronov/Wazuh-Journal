# Wazuh Journal — инструкции для агентов

## Назначение

Внутренний SOC-интерфейс для просмотра алертов Wazuh в виде ленты. События группируются пачками по пять; отдельный алерт можно отправить в OpenAI-совместимый API для оценки ложного срабатывания и черновика XML-правила.

## Структура

- `app/page.tsx` — основной экран, демонстрационные алерты и интерактивные сценарии.
- `app/globals.css` — визуальная система Monad: parchment, serif + monospace, hairline borders, pill-кнопки.
- `app/api/analyze/route.ts` — серверный endpoint анализа одного алерта.
- `.env.example` — переменные Wazuh SSH, Active Directory и OpenAI-compatible API.
- `public/og.png` — Open Graph-обложка.
- `.openai/hosting.json` — Sites-конфигурация; `project_id` не менять вручную.

## Команды

```bash
npm run dev
npm run build
npm test
npm run lint
```

Перед публикацией обязательно выполнить `npm run build`. Environment variables хранить в Sites runtime, не в Git.

## Интеграции

`WAZUH_SSH_HOST`, `WAZUH_SSH_PORT`, `WAZUH_SSH_USER`, `WAZUH_SSH_PRIVATE_KEY` предназначены для server-side SSH bridge. Не помещать ключи в клиентский код, `public/` или browser storage. Текущий UI использует демонстрационные данные.

`AD_TENANT_ID`, `AD_CLIENT_ID`, `AD_CLIENT_SECRET` предназначены для серверной авторизации. Проверку пользователя и права доступа выполнять на сервере или через Sites access policy.

`app/api/analyze/route.ts` отправляет только один алерт на `${OPENAI_BASE_URL}/chat/completions`. Используются `OPENAI_BASE_URL`, `OPENAI_API_KEY`, `OPENAI_MODEL`; секреты никогда не логировать.

## Правила изменений

- Сохранять русский язык интерфейса и стиль Monad.
- Использовать `#f6f3f1` как фон, `#242424` как основной текст, `#cecac8` для границ, `#2b59d1` только для главного действия.
- Не добавлять стандартный SaaS-dashboard, тяжёлые тени, острые углы или новые яркие акценты.
- AI-анализ всегда отправляет один выбранный алерт, не всю пачку.
- XML-правило считать черновиком: перед записью в Wazuh валидировать синтаксис и область действия.
- Кнопка добавления правила в прототипе меняет локальное состояние; production-версия должна писать через защищённый backend и вести аудит.

## Ограничения

Данные Wazuh, SSH bridge, production Active Directory flow и запись правил пока не подключены полностью. D1/R2 не используется без отдельного требования.
