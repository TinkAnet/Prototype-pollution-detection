function guardarAlmacenamientoLocal(llave, valor_a_guardar) {
    localStorage.setItem(llave, JSON.stringify(valor_a_guardar));
}

function obtenerAlmacenamientoLocal(llave) {
    return JSON.parse(localStorage.getItem(llave)) || [];
}

// Mostrar productos en la página
window.addEventListener('load', () => {
    const contenedor = document.getElementById('contenedor');
    const productos = obtenerAlmacenamientoLocal('productos');

    productos.forEach(producto => {
        contenedor.innerHTML += `
            <div class="bg-white shadow-md p-2 rounded-lg">
                <img class="imgc w-full rounded-lg" src="${producto.urlImagen}" alt="${producto.nombre}">
                <div class="informacion">
                    <p class="text-lg font-bold">${producto.nombre}</p>
                    <p class="precio">$${producto.valor}</p>
                    <button class="btn-comprar mt-2 bg-blue-600 text-white py-1 px-4 rounded hover:bg-blue-500" data-producto='${JSON.stringify(producto)}'>Comprar</button>
                </div>
            </div>
        `;
    });

    const botonesComprar = document.querySelectorAll('.btn-comprar');
    botonesComprar.forEach(boton => {
        boton.addEventListener('click', () => {
            const productoSeleccionado = JSON.parse(boton.dataset.producto);
            añadirAlCarrito(productoSeleccionado);
        });
    });
});

// Simulador de Finanzas
document.getElementById("calcular").addEventListener("click", () => {
    const Meta = parseFloat(document.getElementById("Meta").value);
    const Tiempo = parseFloat(document.getElementById("Tiempo").value);
    const ahorroInicial = parseFloat(document.getElementById("ahorroInicial").value);

    const mensaje = isNaN(Meta) || isNaN(Tiempo) || isNaN(ahorroInicial) || Meta <= 0 || Tiempo <= 0 || ahorroInicial < 0
        ? "Por favor, ingrese valores válidos."
        : `Necesitas ahorrar $${((Meta - ahorroInicial) / Tiempo).toFixed(2)} por mes.`;

    document.getElementById("resultado1").textContent = mensaje;

    if (!isNaN(Meta) && !isNaN(Tiempo) && !isNaN(ahorroInicial) && Meta > 0 && Tiempo > 0 && ahorroInicial >= 0) {
        mostrarGrafica(Meta, Tiempo, ahorroInicial);
    }
    limpiarCampos('form1');
});

// Conversión de Moneda (Formulario 2)
document.getElementById("Cambio").addEventListener("click", async () => {
    const MontoOriginal = parseFloat(document.getElementById("MontoOriginal").value);
    const resultadoElemento = document.getElementById("resultado"); // Elemento donde mostrar el resultado
    const monedaDestino = "USD"; // Moneda destino
    const monedaBase = "EUR"; // Moneda base para la API

    // Validar el monto ingresado
    if (isNaN(MontoOriginal) || MontoOriginal <= 0) {
        resultadoElemento.textContent = "Por favor, ingrese un monto válido.";
        return;
    }

    try {
        // Llamar a la API para obtener la tasa de cambio
        const response = await fetch(`https://api.exchangerate.host/latest?base=${monedaBase}`);
        if (!response.ok) throw new Error("Error al obtener datos de la API.");
        
        const data = await response.json();
        const tasaDeCambio = data.rates[monedaDestino];

        if (!tasaDeCambio) throw new Error("No se encontró la tasa de cambio.");

        // Mostrar el resultado convertido
        resultadoElemento.textContent = `El monto convertido es ${(MontoOriginal * tasaDeCambio).toFixed(2)} ${monedaDestino}.`;
    } catch (error) {
        console.error(error);
        resultadoElemento.textContent = "Error al obtener tasas de cambio. Intente nuevamente.";
    }

    // Limpiar campos después de la conversión
    limpiarCampos('form2');
});


// Calculadora de Presupuesto Mensual
document.getElementById("CalcularPresupuesto").addEventListener("click", () => {
    const Ingresos = parseFloat(document.getElementById("IngresosMensuales").value);
    const Alimento = parseFloat(document.getElementById("GastosAlimento").value);
    const Transporte = parseFloat(document.getElementById("GastosTrasporte").value);

    const mensaje = isNaN(Ingresos) || isNaN(Alimento) || isNaN(Transporte) || Ingresos <= 0 || Alimento < 0 || Transporte < 0
        ? "Por favor, ingrese valores válidos."
        : `Tu presupuesto restante es $${(Ingresos - (Alimento + Transporte)).toFixed(2)}.`;

    document.getElementById("resultado3").textContent = mensaje;
    limpiarCampos('form3');
});

// Mostrar gráfica de ahorro más compacta
function mostrarGrafica(meta, tiempo, ahorroInicial) {
    const ctx = document.getElementById("grafica").getContext("2d");
    const ahorroMensual = (meta - ahorroInicial) / tiempo;

    if (window.miGrafica) {
        window.miGrafica.destroy();
    }

    window.miGrafica = new Chart(ctx, {
        type: "bar",
        data: {
            labels: Array.from({ length: tiempo }, (_, i) => `Mes ${i + 1}`),
            datasets: [{
                label: "Ahorro Mensual",
                data: Array(tiempo).fill(ahorroMensual),
                backgroundColor: "rgba(75, 192, 192, 0.6)",
                borderColor: "rgba(75, 192, 192, 1)",
                borderWidth: 1,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                }
            }
        }
    });

    document.querySelector('.contenedorGrafica').style.height = '300px';
}

// Función para limpiar campos de un formulario
function limpiarCampos(formId) {
    document.getElementById(formId).reset();
}

// Manejar productos predefinidos
document.addEventListener("DOMContentLoaded", () => {
    const botonesPredefinidos = document.querySelectorAll(".btn-comprar-predefinido");

    botonesPredefinidos.forEach(boton => {
        boton.addEventListener("click", () => {
            const producto = JSON.parse(boton.dataset.producto);
            añadirAlCarrito(producto);
        });
    });
});

// Función para añadir productos al carrito
function añadirAlCarrito(producto) {
    const carrito = obtenerAlmacenamientoLocal("carrito");

    const productoExistente = carrito.find(item => item.id === producto.id);

    if (productoExistente) {
        productoExistente.cantidad += 1;
    } else {
        carrito.push({ ...producto, cantidad: 1 });
    }

    guardarAlmacenamientoLocal("carrito", carrito);
    actualizarCarritoUI();
    actualizarContadorCarrito();

    Swal.fire({
        title: "¡Producto añadido!",
        html: `Producto "<strong>${producto.nombre}</strong>" se agregó al carrito.`,
        icon: "success",
        confirmButtonText: "Aceptar",
    });
}

// Función para actualizar el contador del carrito
function actualizarContadorCarrito() {
    const carrito = obtenerAlmacenamientoLocal("carrito");
    const contadorCarrito = document.getElementById("cartCounter");
    contadorCarrito.textContent = carrito.reduce((total, item) => total + item.cantidad, 0);
}
