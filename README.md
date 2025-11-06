# Casos de Vulnerabilidades en API

Este documento presenta un análisis técnico de diversas vulnerabilidades identificadas en una aplicación basada en **FastAPI**.  
Cada caso se encuentra alineado con las categorías del estándar **OWASP API Security Top 10 - 2023** y contiene su respectiva explotación, código vulnerable y propuesta de mitigación.

---

## 1. Unrestricted Menu Item Deletion

### Vulnerabilidad
**Tipo:** OWASP API5:2023 – Autorización de Nivel de Función Rota  
La API permite que usuarios con el rol *Customer* eliminen ítems del menú, una función que debería estar limitada a roles superiores.
<img width="921" height="462" alt="image" src="https://github.com/user-attachments/assets/20bb05e5-6087-41b5-b0a1-dd95c3f7e8c7" />


### Explotación
1. Se crea un usuario con rol `Customer`.
2. Se genera un token JWT con sus credenciales.
<img width="921" height="208" alt="image" src="https://github.com/user-attachments/assets/a0ac4ce3-64d5-4266-9169-342c1d51713c" />
3. Se ejecuta una petición:
   ```http
   DELETE /menu/{item_id}

   ```
   <img width="921" height="199" alt="image" src="https://github.com/user-attachments/assets/1d7a47fc-d76f-4eb4-b07f-ea8023558f63" />

4. La operación se completa con éxito, eliminando un ítem que el usuario no debería poder borrar.
<img width="921" height="578" alt="image" src="https://github.com/user-attachments/assets/54608ff7-98e7-4125-b398-287b4ec31c32" />

  


### Código Vulnerable
```python
@router.delete("/menu/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_menu_item(item_id: int, current_user: Annotated[User, Depends(get_current_user)], db: Session = Depends(get_db)):
    utils.delete_menu_item(db, item_id)
```

### Propuesta de Corrección
Agregar control de acceso basado en roles utilizando `RolesBasedAuthChecker`:

```python
@router.delete("/menu/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_menu_item(
    item_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
    auth=Depends(RolesBasedAuthChecker([UserRole.EMPLOYEE, UserRole.CHEF])),
):
    utils.delete_menu_item(db, item_id)
```

**Mitigación:** Solo los roles `EMPLOYEE` y `CHEF` pueden eliminar ítems del menú.

---
<img width="921" height="226" alt="image" src="https://github.com/user-attachments/assets/a1fad6fb-a4cd-4c5e-b0e5-19d9904ca70f" />


## 2. Unrestricted Profile Update (IDOR)

### Vulnerabilidad
**Tipo:** OWASP API1:2023 – Autorización de Nivel de Objeto Rota (BOLA)  
La API no verifica la propiedad del objeto, lo que permite a un usuario actualizar el perfil de otro mediante la manipulación del campo `username`.

<img width="921" height="190" alt="image" src="https://github.com/user-attachments/assets/c157db20-50b0-45a3-9930-900f5a07a55c" />


### Explotación
- El usuario *Niespihu* con su JWT modifica el número telefónico del usuario *Santi*.

<img width="921" height="271" alt="image" src="https://github.com/user-attachments/assets/1fad89e9-5f68-4462-a2cd-c8e207fd2e85" />

- Se confirma el cambio al consultar `GET /profile`.
<img width="921" height="188" alt="image" src="https://github.com/user-attachments/assets/bac6cbeb-1efd-4202-961e-b4d3c0303c61" />


### Código Vulnerable
```python
db_user = get_user_by_username(db, user.username)
```

### Propuesta de Corrección
Utilizar el nombre del usuario autenticado para garantizar la integridad del proceso:

```python
db_user = get_user_by_username(db, current_user.username)
```

**Mitigación:** Solo el propietario del perfil puede modificar sus propios datos.

---
<img width="921" height="298" alt="image" src="https://github.com/user-attachments/assets/7fc166fd-924c-4a29-81bb-013bb84cf002" />


## 3. Privilege Escalation

### Vulnerabilidad
**Tipo:** OWASP API5:2023 – Autorización de Nivel de Función Rota  
El endpoint permite que cualquier usuario modifique roles de otros, generando una escalada de privilegios no autorizada.

<img width="921" height="188" alt="image" src="https://github.com/user-attachments/assets/565fc867-707d-4f6e-878a-2839cb52d119" />


### Explotación
Un usuario con rol `Consumer` ejecuta una solicitud a:
```http
PUT /users/update_role
```
y logra modificar roles sin la debida autorización.
<img width="921" height="253" alt="image" src="https://github.com/user-attachments/assets/0caa63d1-055f-4e99-81a3-1f64ccf5d719" />


### Código Vulnerable
```python
@router.put("/users/update_role")
async def update_user_role(user: UserRoleUpdate, current_user: Annotated[models.User, Depends(get_current_user)], db: Session = Depends(get_db)):
    db_user = update_user(db, user.username, user)
    return current_user
```

### Propuesta de Corrección
Aplicar control de roles mediante `RolesBasedAuthChecker`:

```python
@router.put("/users/update_role")
async def update_user_role(
    user: UserRoleUpdate,
    current_user: Annotated[models.User, Depends(get_current_user)],
    db: Session = Depends(get_db),
    auth=Depends(RolesBasedAuthChecker([models.UserRole.EMPLOYEE, models.UserRole.CHEF]))
):
    if user.role == models.UserRole.CHEF.value:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Only Chef is authorized to add Chef role!")
    db_user = update_user(db, user.username, user)
    return current_user
```

**Mitigación:** Solo los roles `EMPLOYEE` y `CHEF` pueden ejecutar cambios de rol.

---

<img width="921" height="283" alt="image" src="https://github.com/user-attachments/assets/dec681d6-a9f8-4b5b-ab77-5e568e70a3ea" />

## 4. Server Side Request Forgery (SSRF)

### Vulnerabilidad
**Tipo:** OWASP API7:2023 – Falsificación de Solicitud del Lado del Servidor (SSRF)  
El endpoint `PUT /menu` permite enviar URLs externas en el campo `image_url`, lo que posibilita que el servidor realice solicitudes internas no autorizadas.
<img width="921" height="231" alt="image" src="https://github.com/user-attachments/assets/be503538-92cd-451c-8624-5d9ea26c990b" />


### Explotación
Un atacante envía la siguiente URL:
```
http://localhost:8091/admin/reset-chef-password
```
El servidor procesa la solicitud interna y modifica información sensible.

<img width="921" height="207" alt="image" src="https://github.com/user-attachments/assets/c56b3734-144c-4f69-917f-f0e2300f9196" />
<img width="921" height="187" alt="image" src="https://github.com/user-attachments/assets/28c19029-3624-45c8-8b5b-975edd51385f" />



### Código Vulnerable
```python
def _image_url_to_base64(image_url: str):
    response = requests.get(image_url, stream=True)
    return base64.b64encode(response.content).decode()
```

### Propuesta de Corrección
Validar dominios y tipos de archivo antes de procesar la imagen:

```python
def _image_url_to_base64(url_imagen: str) -> str:
    url_analizada = urlparse(url_imagen)
    dominio = url_analizada.hostname or ""

    dominios_permitidos = ["localhost", "127.0.0.1"]
    if dominio not in dominios_permitidos:
        raise Exception(f"Dominio no permitido: {dominio}")

    extensiones_validas = (".jpg", ".jpeg", ".png", ".gif")
    ruta_archivo = url_analizada.path.lower()
    if not ruta_archivo.endswith(extensiones_validas):
        raise Exception("Extensión de archivo no válida")

    respuesta = requests.get(url_imagen, stream=True)
    if not respuesta.headers.get("content-type", "").startswith("image"):
        raise Exception("La URL no apunta a una imagen válida")

    return base64.b64encode(respuesta.content).decode()
```

**Mitigación:** Se restringen los dominios y se valida el contenido de las imágenes.

---

<img width="921" height="301" alt="image" src="https://github.com/user-attachments/assets/7f86c430-e08d-421e-904e-5e41ddae1b8e" />


## 5. JWT Authentication Bypass – Weak Signing Key

### Vulnerabilidad
**Tipo:** OWASP API2:2023 – Autenticación Rota  
Los JWT se firmaban con claves débiles (de 6 dígitos) y sin verificación de firma, permitiendo la falsificación y ataques de repetición.
<img width="921" height="224" alt="image" src="https://github.com/user-attachments/assets/33ba1ee5-845d-4fe0-bc9f-5cb37c31f550" />


### Explotación
- Se analiza el token en **jwt.io**, evidenciando el uso de HS256 y clave simple.
<img width="921" height="531" alt="image" src="https://github.com/user-attachments/assets/527c5815-6c96-43b5-831a-24895f02a26f" />

- Se realiza un ataque de fuerza bruta con **Hashcat**:
  ```bash
  hashcat -m 16500 -a 3 jwt.txt '?d?d?d?d?d?d'
  ```
  <img width="921" height="459" alt="image" src="https://github.com/user-attachments/assets/e1c3eaa5-ca0f-4cae-935d-83117682445b" />

- La clave obtenida permite generar tokens válidos sin autorización.

### Código Vulnerable
```python
VERIFY_SIGNATURE = False
```

### Propuesta de Corrección
Usar un algoritmo asimétrico robusto (RS256) y llaves privadas/públicas generadas con OpenSSL.

#### Generación de Llaves
```bash
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in private.pem -pubout -out public.pem
```

#### Código Mejorado
```python
ALGORITHM = "RS256"
_KEY_DIR = Path(__file__).resolve().parent
PRIVATE_KEY = (_KEY_DIR / "private.pem").read_bytes()
PUBLIC_KEY = (_KEY_DIR / "public.pem").read_bytes()
```

**Mitigación:** La autenticación ahora se basa en criptografía fuerte y validación de firma.

---

<img width="921" height="558" alt="image" src="https://github.com/user-attachments/assets/fbbae408-865b-4d67-8f5c-7949ced38dc0" />


## Conclusiones

El conjunto de vulnerabilidades detectadas demuestra la relevancia de implementar controles de seguridad adecuados en las APIs modernas.  
Se recomienda aplicar prácticas de **autenticación sólida**, **autorización basada en roles**, **validación de entradas** y **gestión segura de tokens** para garantizar la integridad y confidencialidad de los sistemas.

---
