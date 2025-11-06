# Casos de Vulnerabilidades en API

Este documento presenta un análisis técnico de diversas vulnerabilidades identificadas en una aplicación basada en **FastAPI**.  
Cada caso se encuentra alineado con las categorías del estándar **OWASP API Security Top 10 - 2023** y contiene su respectiva explotación, código vulnerable y propuesta de mitigación.

---

## 1. Unrestricted Menu Item Deletion

### Vulnerabilidad
**Tipo:** OWASP API5:2023 – Autorización de Nivel de Función Rota  
La API permite que usuarios con el rol *Customer* eliminen ítems del menú, una función que debería estar limitada a roles superiores.

### Explotación
1. Se crea un usuario con rol `Customer`.
2. Se genera un token JWT con sus credenciales.
3. Se ejecuta una petición:
   ```http
   DELETE /menu/{item_id}
   ```
4. La operación se completa con éxito, eliminando un ítem que el usuario no debería poder borrar.
   <img width="921" height="188" alt="image" src="https://github.com/user-attachments/assets/e224d839-fdc8-40d3-b316-2a24caa82d33" />


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

## 2. Unrestricted Profile Update (IDOR)

### Vulnerabilidad
**Tipo:** OWASP API1:2023 – Autorización de Nivel de Objeto Rota (BOLA)  
La API no verifica la propiedad del objeto, lo que permite a un usuario actualizar el perfil de otro mediante la manipulación del campo `username`.

### Explotación
- El usuario *Niespihu* con su JWT modifica el número telefónico del usuario *Santi*.
- Se confirma el cambio al consultar `GET /profile`.

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

## 3. Privilege Escalation

### Vulnerabilidad
**Tipo:** OWASP API5:2023 – Autorización de Nivel de Función Rota  
El endpoint permite que cualquier usuario modifique roles de otros, generando una escalada de privilegios no autorizada.

### Explotación
Un usuario con rol `Consumer` ejecuta una solicitud a:
```http
PUT /users/update_role
```
y logra modificar roles sin la debida autorización.

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

## 4. Server Side Request Forgery (SSRF)

### Vulnerabilidad
**Tipo:** OWASP API7:2023 – Falsificación de Solicitud del Lado del Servidor (SSRF)  
El endpoint `PUT /menu` permite enviar URLs externas en el campo `image_url`, lo que posibilita que el servidor realice solicitudes internas no autorizadas.

### Explotación
Un atacante envía la siguiente URL:
```
http://localhost:8091/admin/reset-chef-password
```
El servidor procesa la solicitud interna y modifica información sensible.

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

## 5. JWT Authentication Bypass – Weak Signing Key

### Vulnerabilidad
**Tipo:** OWASP API2:2023 – Autenticación Rota  
Los JWT se firmaban con claves débiles (de 6 dígitos) y sin verificación de firma, permitiendo la falsificación y ataques de repetición.

### Explotación
- Se analiza el token en **jwt.io**, evidenciando el uso de HS256 y clave simple.
- Se realiza un ataque de fuerza bruta con **Hashcat**:
  ```bash
  hashcat -m 16500 -a 3 jwt.txt '?d?d?d?d?d?d'
  ```
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

## Conclusiones

El conjunto de vulnerabilidades detectadas demuestra la relevancia de implementar controles de seguridad adecuados en las APIs modernas.  
Se recomienda aplicar prácticas de **autenticación sólida**, **autorización basada en roles**, **validación de entradas** y **gestión segura de tokens** para garantizar la integridad y confidencialidad de los sistemas.

---
