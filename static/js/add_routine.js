// add_routine.js - Manages add routine form behavior

document.addEventListener('DOMContentLoaded', function() {
    const scheduleTypeSelect = document.getElementById('schedule_type');
    const timeField = document.getElementById('schedule_time');

    // Function to update the time field state
    function updateTimeFieldState() {
        if (scheduleTypeSelect.value === 'manual') {
            timeField.required = false;
            timeField.disabled = true;
        } else {
            timeField.required = true;
            timeField.disabled = false;
        }
    }

    // Initialize correct state on page load
    updateTimeFieldState();

    // Add listener for schedule type changes
    scheduleTypeSelect.addEventListener('change', updateTimeFieldState);
});
