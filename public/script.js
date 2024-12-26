// Initialize the QR code scanner
document.addEventListener("DOMContentLoaded", function(){
    const html5QrCode = new Html5Qrcode("reader");
   
    // This method will trigger user permissions
    Html5Qrcode.getCameras().then(devices => {
        /**
         * devices would be an array of objects of type:
         * { id: "id", label: "label" }
         */
        if (devices && devices.length) {
          var cameraId = devices[0].id;
          // .. use this to start scanning.
        }
      }).catch(err => {
        // handle err
      });
      
     // Success callback function
     function onScanSuccess(decodedText, decodedResult) {
         // Populate the input field with the scanned barcode
         document.getElementById("barcode").value = decodedText;
         
         // Optionally, stop scanning after successful read
         html5QrCode.stop().then((ignore) => {
             console.log("QR Code scanning stopped.");
         }).catch((err) => {
             console.error("Failed to stop scanning.", err);
         });
     }

     // Error callback function
     function onScanFailure(error) {
         // Handle scan failure (optional)
         console.warn(`Scan error: ${error}`);
     }

     // Start scanning with user-facing camera
     const config = { fps: 10, qrbox: { width: 150, height: 150 } };
     
     html5QrCode.start({ facingMode: "environment" }, config, onScanSuccess, onScanFailure)
         .catch((err) => {
             console.error("Unable to start scanning.", err);
         });

    // Handle form submission
    document.getElementById("assetForm").addEventListener("submit", async function(event) {
        event.preventDefault();
        const barcode = document.getElementById("barcode").value;
        const assetName = document.getElementById("assetName").value;
        const lab = document.getElementById("lab").value;
        const date = document.getElementById("date").value;

        try {
            const token = localStorage.getItem('token');
            if (!token) {
                alert('You must be logged in to submit an asset');
                window.location.href = '/login';
                return;
            }

            const response = await fetch('/submit-asset', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ barcode, assetName, lab, date })
            });

            if (response.ok) {
                alert('Asset saved successfully');
                this.reset();
            } else {
                const errorData = await response.json();
                alert(errorData.message || 'Error saving asset');
            }
        } catch (error) {
            console.error('Error:', error);
            alert('An error occurred while saving the asset');
        }
    });
});

