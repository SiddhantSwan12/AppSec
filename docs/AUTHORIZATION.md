# Authorization matrix

Permissions are enforced by Express and SQL predicates. Hiding navigation is only presentation. For inaccessible private resources, 404 avoids distinguishing nonexistent objects from someone else's objects.

| Operation                            | Anonymous                | Owner / participant                  | Another normal user                 | Admin                                        |
| ------------------------------------ | ------------------------ | ------------------------------------ | ----------------------------------- | -------------------------------------------- |
| Register, login, request/use reset   | Allowed with CSRF/Origin | Allowed with CSRF/Origin             | Allowed with CSRF/Origin            | Allowed with CSRF/Origin                     |
| Current wallet/profile/session       | 401                      | Own account only                     | Cannot select another identity      | Own account only                             |
| Send money                           | 401                      | From own wallet                      | Cannot override sender              | From own wallet only; no privileged transfer |
| Transaction detail/history           | 401                      | Sender or recipient                  | 404 for detail; excluded from lists | Same participant rule on user endpoints      |
| Create ticket                        | 401                      | Creates owned ticket                 | Cannot set owner                    | Creates owned ticket                         |
| Ticket detail/reply                  | 401                      | Allowed; replies require open ticket | 404                                 | Allowed for support duties                   |
| Current ticket list                  | 401                      | Own tickets                          | Cannot select another owner         | Own tickets; all tickets via admin list      |
| Admin users/transfers/tickets/events | 401                      | 403 for normal users                 | 403                                 | Read-only lists                              |
| Change ticket status                 | 401                      | 403 for normal owners                | 403                                 | Allowed                                      |
| Assign role through public API       | Rejected                 | Rejected                             | Rejected                            | No such endpoint                             |
| Arbitrarily edit balances            | No endpoint              | No endpoint                          | No endpoint                         | No endpoint                                  |

`security-runner/rules.json` instantiates ticket and admin-list expectations using only seeded resources. API integration tests cover further transfer ownership, role restrictions, protected fields, and ticket mutations.
