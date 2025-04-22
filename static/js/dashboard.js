// Toggle Sidebar
const sidebarToggle = document.getElementById('sidebar-toggle');
const sidebar = document.getElementById('sidebar');
const content = document.querySelector('.content');

sidebarToggle.addEventListener('click', () => {
  sidebar.classList.toggle('collapsed');
  content.classList.toggle('expanded');
});

// Change Content Based on Sidebar Buttons
document.querySelectorAll('.menu-btn').forEach(button => {
  button.addEventListener('click', () => {
    const targetContent = button.dataset.content;
    document.querySelectorAll('.content-section').forEach(section => {
      section.classList.remove('active');
      section.style.display = 'none'; // Add this line
    });
    document.getElementById(targetContent).classList.add('active');
    document.getElementById(targetContent).style.display = 'block'; // Add this line
  });
});