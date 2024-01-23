function submitForm() {
  // Show loading animation
  document.getElementById("loading").style.display = "block";

  // Hide result section
  document.getElementById("result").style.display = "none";

  // Submit the form
  document.getElementById("phishingForm").submit();
}
