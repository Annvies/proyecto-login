const formulario = document.getElementById("formulario");
const email = document.getElementById("email");
const password = document.getElementById("password");
const mensaje = document.getElementById("mensaje");
const enviar = document.getElementById("enviar");
const titulo = document.getElementById("titulo");
const pestanas = document.querySelector(".pestanas");
const tabLogin = document.getElementById("tab-login");
const tabRegistro = document.getElementById("tab-registro");
const perfil = document.getElementById("perfil");
const correoPerfil = document.getElementById("correo-perfil");
const cerrarSesion = document.getElementById("cerrar-sesion");

const CLAVE_TOKEN = "token";
const PATRON_CORREO = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
let modo = "login";

function mostrarMensaje(texto, tipo = "") {
  mensaje.textContent = texto;
  mensaje.classList.remove("error", "exito");
  if (tipo) mensaje.classList.add(tipo);
}

function validarCampos() {
  if (!PATRON_CORREO.test(email.value.trim())) {
    return "Escribe un correo válido, por ejemplo usuario@dominio.com.";
  }
  if (password.value.length < 8) {
    return "La contraseña debe tener al menos 8 caracteres.";
  }
  return "";
}

function activarCarga(activo) {
  enviar.disabled = activo;
  enviar.textContent = activo
    ? "Procesando…"
    : modo === "login" ? "Entrar" : "Registrarse";
}

function cambiarModo(nuevo) {
  modo = nuevo;
  const esLogin = modo === "login";
  titulo.textContent = esLogin ? "Iniciar sesión" : "Crear cuenta";
  enviar.textContent = esLogin ? "Entrar" : "Registrarse";
  tabLogin.classList.toggle("activa", esLogin);
  tabRegistro.classList.toggle("activa", !esLogin);
  tabLogin.setAttribute("aria-selected", String(esLogin));
  tabRegistro.setAttribute("aria-selected", String(!esLogin));
  password.autocomplete = esLogin ? "current-password" : "new-password";
  mostrarMensaje("");
}

function mostrarPerfil(correo) {
  formulario.hidden = true;
  pestanas.hidden = true;
  perfil.hidden = false;
  titulo.textContent = "Sesión iniciada";
  correoPerfil.textContent = correo;
  mostrarMensaje("");
}

function volverAlFormulario() {
  perfil.hidden = true;
  formulario.hidden = false;
  pestanas.hidden = false;
  formulario.reset();
  cambiarModo("login");
  email.focus();
}

function textoDeError(estado, datos) {
  if (datos && datos.error) return datos.error;
  if (estado === 400) return "Revisa los datos: correo válido y contraseña de al menos 8 caracteres.";
  if (estado === 401) return "Correo o contraseña incorrectos.";
  if (estado === 409) return "Ese correo ya está registrado.";
  return "No se pudo completar la operación. Inténtalo de nuevo.";
}

async function solicitar(ruta, cuerpo) {
  const respuesta = await fetch(ruta, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(cuerpo),
  });
  let datos = {};
  try {
    datos = await respuesta.json();
  } catch (error) {
    datos = {};
  }
  return { estado: respuesta.status, datos };
}

async function cargarPerfil() {
  const token = localStorage.getItem(CLAVE_TOKEN);
  if (!token) return;
  try {
    const respuesta = await fetch("/api/me", {
      headers: { Authorization: "Bearer " + token },
    });
    if (respuesta.status === 401) {
      localStorage.removeItem(CLAVE_TOKEN);
      return;
    }
    const datos = await respuesta.json();
    if (datos.ok) mostrarPerfil(datos.email);
  } catch (error) {
    localStorage.removeItem(CLAVE_TOKEN);
  }
}

tabLogin.addEventListener("click", () => cambiarModo("login"));
tabRegistro.addEventListener("click", () => cambiarModo("registro"));

formulario.addEventListener("submit", async (evento) => {
  evento.preventDefault();

  const aviso = validarCampos();
  if (aviso) {
    mostrarMensaje(aviso, "error");
    return;
  }

  const ruta = modo === "login" ? "/api/login" : "/api/register";
  activarCarga(true);
  mostrarMensaje("");

  try {
    const { estado, datos } = await solicitar(ruta, {
      email: email.value.trim(),
      password: password.value,
    });

    if (!datos.ok) {
      mostrarMensaje(textoDeError(estado, datos), "error");
      return;
    }

    if (modo === "registro") {
      formulario.reset();
      cambiarModo("login");
      mostrarMensaje("Cuenta creada. Ahora puedes iniciar sesión.", "exito");
      email.focus();
      return;
    }

    localStorage.setItem(CLAVE_TOKEN, datos.token);
    mostrarPerfil(datos.email);
  } catch (error) {
    mostrarMensaje("No hay conexión con el servidor. Inténtalo de nuevo.", "error");
  } finally {
    activarCarga(false);
  }
});

cerrarSesion.addEventListener("click", () => {
  localStorage.removeItem(CLAVE_TOKEN);
  volverAlFormulario();
  mostrarMensaje("Has cerrado sesión.", "exito");
});

cargarPerfil();
