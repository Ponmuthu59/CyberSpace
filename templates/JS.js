
// <!-- SQL Injection Main Displaying -->

function sqlclick() {
  // Get the container where inner HTML will be displayed
  const innerContent = document.getElementById("innerContent");
  
  // Set the inner HTML content
  innerContent.innerHTML = `
       <div class="box" id="sql1">
<h2 class="stopic">SQL Injection Testing</h2>
<form action="/test_sql_injection" method="POST">
<label for="sql_url" class="sub1">Enter URL for SQL Injection Test:</label>
<input type="text" id="sql_url" name="url" class="sub2" required><br>
<button type="submit" class="btn1">Test SQL Injection</button>
</form>
</div>
  `;
  
  // Show the inner content
  innerContent.style.display = "block"; // Change to "block" to make it visible
}




// <!-- Port Scanning Form -->

function psclick() {
// Get the container where inner HTML will be displayed
const innerContent = document.getElementById("innerContent");

// Set the inner HTML content
innerContent.innerHTML = `
<div class="box" id="ps1">
<h2 class="stopic">Port Scanning</h2>
<form action="/scan_ports" method="POST">
<label for="target_ip">Enter Target IP:</label>
<input type="text" id="target_ip" name="target_ip" required><br>
<label for="port_range" style="margin-top: 10px;">Port Range:</label>
<select id="port_range">
    <option value="21-FTP">21-FTP</option>
    <option value="22-SSH">22-SSH</option>
    <option value="23-TELNET">23-TELNET</option>
    <option value="25-SMTP">25-SMTP</option>
    <option value="53-DNS">53-DNS</option>
    <option value="67-DHCP">67-DHCP</option>
    <option value="80-HTTP">80-HTTP</option>
    <option value="443-HTTPS">443-HTTPS</option>
    <option value="123-NTP">123-NTP</option>
    <option value="3389-RDP">3389-RDP</option>
</select><BR>
<button type="submit" class="btn1">Scan Ports</button>
</form>
</div>
`;

// Show the inner content
innerContent.style.display = "block"; // Change to "block" to make it visible
}


// <!-- SSH Brute Force Attack Form -->

function bfclick() {
  // Get the container where inner HTML will be displayed
  const innerContent = document.getElementById("innerContent");
  
  // Set the inner HTML content
  innerContent.innerHTML = `
       <div class="box" id="bf1">
<h2 class="stopic">SSH Brute Force Attack</h2>
<form action="/ssh_brute_force" method="POST">
<label for="ssh_ip">Enter Target IP:</label>
<input type="text" id="ssh_ip" name="target_ip" required><br>
<label for="username">Enter Username:</label>
<input type="text" id="username" name="username" required><br>
<label for="password_list" id="list_name">Enter Password List (comma separated):</label>
<input type="text" id="password_list" name="password_list" required><br>
<button type="submit" class="btn1">Start SSH Brute Force Attack</button>
</form>
</div>

  `;
  
  // Show the inner content
  innerContent.style.display = "block"; // Change to "block" to make it visible
}



// <!-- Denial of Service (DoS) Attack Form -->

function dosclick() {
  // Get the container where inner HTML will be displayed
  const innerContent = document.getElementById("innerContent");
  
  // Set the inner HTML content
  innerContent.innerHTML = `
      <div class="box" id="dos1">
<h2 class="stopic">Denial of Service (DoS) Attack</h2>
<form action="/dos_attack" method="POST">
<label for="dos_url">Enter Target URL:</label>
<input type="text" id="dos_url" name="target_url" required><br>
<label for="threads_count">Number of Threads:</label>
<input type="number" id="threads_count" name="threads_count" min="1" value="5" required><br>
<label for="request_limit">Number of Requests Per Thread:</label>
<input type="number" id="request_limit" name="request_limit" min="1" value="100" required><br>
<button type="submit" class="btn1">Start DoS Attack</button>
</form>
</div>
  `;
  
  // Show the inner content
  innerContent.style.display = "block"; // Change to "block" to make it visible
}



// <!-- XSS Testing Form -->

function xssclick() {
  // Get the container where inner HTML will be displayed
  const innerContent = document.getElementById("innerContent");
  
  // Set the inner HTML content
  innerContent.innerHTML = `
  <div class="box" id="dos1">
    <h2 class="stopic">Cross-Site Scripting (XSS) Testing</h2>
    <form action="/test_xss" method="POST">
        <label for="xss_url">Enter URL for XSS Test:</label>
        <input type="text" id="xss_url" name="url" required><br>
        <button type="submit" class="btn1">Test XSS</button>
    </form>
    </div>
  `;
  
  // Show the inner content
  innerContent.style.display = "block"; // Change to "block" to make it visible
}


// MOVE TO TOP SCROLLING

function movetop() {
  const targetElement = document.getElementById("up1");
  smoothScrollTo(targetElement);
}


// function for smooth scroll

function smoothScrollTo(element) {
  const targetPosition = element.getBoundingClientRect().top + window.pageYOffset;
  const startPosition = window.pageYOffset;
  const distance = targetPosition - startPosition;
  const duration = 1000; // Duration in milliseconds
  let startTime = null;

  function animation(currentTime) {
    if (startTime === null) startTime = currentTime;
    const timeElapsed = currentTime - startTime;
    const progress = Math.min(timeElapsed / duration, 1); // Clamp progress to 1

    // Easing function for smooth scrolling
    const easing = Math.sin(progress * (Math.PI / 2)); // Easing for smoother effect

    window.scrollTo(0, startPosition + distance * easing);

    if (timeElapsed < duration) {
      requestAnimationFrame(animation);
    }
  }

  requestAnimationFrame(animation);
}


// FOR CHATTING

document.addEventListener("DOMContentLoaded", function() {
            // Show the chat box when the chat icon is clicked
            document.getElementById("chat-icon").addEventListener("click", function() {
                document.getElementById("chat-box").style.display = "block";
            });

            // Hide the chat box when the close button is clicked
            document.getElementById("close-btn").addEventListener("click", function() {
                document.getElementById("chat-box").style.display = "none";
            });

            // Add event listener to the send button
            document.getElementById("send-btn").addEventListener("click", function() {
                // Get the value of the input field
                const userInput = document.getElementById("chat-input").value;
                
                // Check if the input is not empty
                if (userInput.trim() !== "") {
                    // Create a new paragraph element for the message
                    const messageElement = document.createElement("p");
                    
                    // Set the message text to the user input
                    messageElement.textContent = userInput;
                    
                    // Append the new message to the chat content
                    document.getElementById("chat-content").appendChild(messageElement);
                    
                    // Clear the input field
                    document.getElementById("chat-input").value = "";
                    
                    // Automatically scroll the chat content to the bottom
                    const chatContent = document.getElementById("chat-content");
                    chatContent.scrollTop = chatContent.scrollHeight;
                }
            });

            // Add event listener for Enter key in input field
            document.getElementById("chat-input").addEventListener("keypress", function(event) {
                if (event.key === "Enter") {
                    document.getElementById("send-btn").click(); // Trigger the send button
                }
            });
        });
