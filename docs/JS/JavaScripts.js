let lastResult = null;

const API_URL = "https://prevencioninyeccionessql.onrender.com";

        function ShowLoading() {
            document.getElementById("loading").style.display = "flex";
        }

        function HideLoading() {
            document.getElementById("loading").style.display = "none";
        }

        async function subirArchivo() {
            let input = document.getElementById("fileInput");            
            let resultado = document.getElementById("resultado");
            let verResultadosbtn = document.getElementById("verResultadosbtn");

            if (input.files.length === 0) {
                alert("Seleccione un archivo antes de verificar el código.");
                return;
            }

            ShowLoading();
            verResultadosbtn.style.display = "none";
            //resultado.style.display = "none";
            //resultado.textContent = "";

            let formData = new FormData();
            formData.append("file", input.files[0]);

            try {
                let response = await fetch('${API_URL}/analizar/', {
                    method: 'POST',
                    body: formData
                });

                console.log("Estado de la respuesta:", response.status);

                if (!response.ok) {
                    let errorText = await response.text();
                    throw new Error(`Error en la API: ${response.status} - ${errorText}`);
                }

                let data = await response.json();
                lastResult = data; // Store the result

                setTimeout(() => {
                    console.log("Respuesta API:", data);

                    HideLoading();
                    verResultadosbtn.style.display = "block";
                    formatRecommendations(data);
                }, 3000);
                
            } catch (error) {
                console.error("Error:", error);
                resultado.textContent = "Error: " + error;
                HideLoading();
            }        
        }

        //Captura hito3
        function mostrarResultados() {
            //let resultado = document.getElementById("resultado");
            //resultado.style.display = "block";
            //resultado.textContent = JSON.stringify(lastResult, null, 4);

            let jsonDoc = new Blob([JSON.stringify(lastResult, null, 4)], { type: "application/json" });
            let url = document.createElement("a");
            url.href = URL.createObjectURL(jsonDoc);
            url.download = "resultado.json";
            url.click();
        }

        
    function formatRecommendations(data) {
        let resultadoContainer = document.getElementById("resultado-container");
        let resultado = document.getElementById("resultado");

        resultado.innerHTML = ""; // Clear previous results
        resultadoContainer.style.display = "block";

        if (data.resultado === "Tu codigo es seguro") {            
            resultado.innerHTML = `<p style="color: green; font-weight: bold;"> ${data.resultado}</p>
                                   <p>No se encontraron vulnerabilidades conocidas.</p>`;
            return;
        }
            
        if (!data.recomendaciones || data.recomendaciones.length === 0) {            
            resultado.innerHTML = `<p style="color: green; font-weight: bold;"> Tu código es seguro</p>
                                   <p>No se encontraron vulnerabilidades conocidas.</p>`;
            return;
        }

        data.recomendaciones.forEach((rec) => {
            let card = document.createElement("div");
            card.style.border = "1px solid #ccc";
            card.style.padding = "15px";
            card.style.margin = "10px 0";
            card.style.borderRadius = "8px";
            card.style.backgroundColor = "#f9f9f9";
            card.style.boxShadow = "2px 2px 5px rgba(0,0,0,0.1)";

            let mensaje = document.createElement("h3");
            mensaje.style.color = "#D9534F"; // Red for warnings
            mensaje.textContent = rec.mensaje;

            let explicacion = document.createElement("p");
            explicacion.style.color = "#5A5A5A";
            explicacion.textContent = rec.explicacion || "No se proporcionó explicación.";

            let codeBlock = document.createElement("pre");
            codeBlock.style.backgroundColor = "#272822";
            codeBlock.style.color = "#FFF";
            codeBlock.style.padding = "10px";
            codeBlock.style.borderRadius = "5px";
            codeBlock.style.overflowX = "auto";
            codeBlock.textContent = rec.ejemplo_corregido;

            card.appendChild(mensaje);
            card.appendChild(explicacion);
            card.appendChild(codeBlock);
            resultado.appendChild(card);
        });
    }

    async function descargarZip() {        
        let Zip = document.getElementById("Zip").value;
    
        ShowLoading();
    
        try {
            let response = await fetch('${API_URL}/Obtener_Recomendaciones/?tipo=${Zip}', { // ✅ Use backticks
                method: 'GET'
            });
    
            if (!response.ok) {
                let errorText = await response.text();
                throw new Error(`Error en la API: ${response.status} - ${errorText}`);
            }
    
            
            let blob = await response.blob();
            let url = window.URL.createObjectURL(blob);
            let a = document.createElement("a");
            a.href = url;
            a.download = `Recomendaciones_${Zip}.zip`;
            document.body.appendChild(a);
            HideLoading();
            a.click();
            document.body.removeChild(a);
    
            console.log("Respuesta API:", response);
    
        } catch (error) {
            console.error("Error:", error);
            alert("Error descargando el archivo: " + error.message); // ✅ Show alert instead of setting `resultado.textContent`
            HideLoading();
        }
    }

    
