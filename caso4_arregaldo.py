def _image_url_to_base64(url_imagen: str) -> str:
    url_analizada = urlparse(url_imagen)
    dominio = url_analizada.hostname or ""
    
    
    dominios_permitidos = ["localhost", "127.0.0.1"]
    if dominio not in dominios_permitidos:
        raise Exception(f"Dominio no permitido: {dominio}")
    
   
    extensiones_validas = (".jpg", ".jpeg", ".png", ".gif")
    ruta_archivo = url_analizada.path.lower()
    
    if not ruta_archivo.endswith(extensiones_validas):
        raise Exception("Extensión de archivo no válida. Use: jpg, jpeg, png o gif")
    
   
    respuesta = requests.get(url_imagen, stream=True)
    tipo_contenido = respuesta.headers.get("content-type", "")
    
   
    if not tipo_contenido.startswith("image"):
        raise Exception("La URL no apunta a una imagen válida")
    
  
    imagen_codificada = base64.b64encode(respuesta.content).decode()
    
    return imagen_codificada
