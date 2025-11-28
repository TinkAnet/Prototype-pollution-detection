// Mobile Navigation
const navToggle = document.querySelector('.mobile-nav-toggle');
const primaryNav = document.querySelector('.main-nav');

if (navToggle && primaryNav) {
  navToggle.addEventListener('click', () => {
    const isVisible = primaryNav.getAttribute('data-visible') === 'true';
    primaryNav.setAttribute('data-visible', !isVisible);
    navToggle.setAttribute('aria-expanded', !isVisible);
  });
}

// Toast Notifications
class Toast {
  constructor(type = 'info', message = '', duration = 3000) {
    this.type = type;
    this.message = message;
    this.duration = duration;
  }

  show() {
    const toast = document.createElement('div');
    toast.className = `toast ${this.type}`;
    toast.setAttribute('role', 'alert');
    toast.textContent = this.message;
    
    document.body.appendChild(toast);
    
    // Trigger reflow for animation
    toast.offsetHeight;
    
    setTimeout(() => {
      toast.style.opacity = '0';
      setTimeout(() => {
        document.body.removeChild(toast);
      }, 300);
    }, this.duration);
  }
}

// Loading State Handler
class LoadingState {
  static add(element) {
    element.classList.add('loading');
    element.setAttribute('aria-busy', 'true');
  }

  static remove(element) {
    element.classList.remove('loading');
    element.setAttribute('aria-busy', 'false');
  }
}

// Form Validation
class FormValidator {
  static validate(form) {
    const inputs = form.querySelectorAll('input, select, textarea');
    let isValid = true;

    inputs.forEach(input => {
      if (!input.checkValidity()) {
        isValid = false;
        this.showError(input);
      } else {
        this.clearError(input);
      }
    });

    return isValid;
  }

  static showError(input) {
    const errorMessage = input.validationMessage;
    const errorElement = document.createElement('div');
    errorElement.className = 'error-message';
    errorElement.textContent = errorMessage;
    
    // Remove any existing error message
    this.clearError(input);
    
    input.parentNode.appendChild(errorElement);
    input.setAttribute('aria-invalid', 'true');
  }

  static clearError(input) {
    const existingError = input.parentNode.querySelector('.error-message');
    if (existingError) {
      existingError.remove();
    }
    input.setAttribute('aria-invalid', 'false');
  }
}

// Dark Mode Toggle
class ThemeToggle {
  constructor() {
    this.theme = localStorage.getItem('theme') || 'light';
    this.init();
  }

  init() {
    document.documentElement.setAttribute('data-theme', this.theme);
    
    const toggle = document.querySelector('.theme-toggle');
    if (toggle) {
      toggle.setAttribute('aria-label', `Switch to ${this.theme === 'light' ? 'dark' : 'light'} mode`);
      toggle.addEventListener('click', () => this.toggle());
    }
  }

  toggle() {
    this.theme = this.theme === 'light' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', this.theme);
    localStorage.setItem('theme', this.theme);
  }
}

// Initialize features
document.addEventListener('DOMContentLoaded', () => {
  new ThemeToggle();

  // Add form validation
  document.querySelectorAll('form').forEach(form => {
    form.addEventListener('submit', (e) => {
      if (!FormValidator.validate(form)) {
        e.preventDefault();
      }
    });
  });

  // Example usage of toast
  // new Toast('success', 'Welcome back!').show();
});

// Intersection Observer for lazy loading
const lazyLoadObserver = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      const target = entry.target;
      if (target.tagName.toLowerCase() === 'img') {
        target.src = target.dataset.src;
        target.classList.remove('lazy');
        lazyLoadObserver.unobserve(target);
      }
    }
  });
});

// Apply lazy loading to images
document.querySelectorAll('img[data-src]').forEach(img => {
  img.classList.add('lazy');
  lazyLoadObserver.observe(img);
});

// Task Bubble Hover Effect
document.addEventListener('DOMContentLoaded', function() {
    const taskDays = document.querySelectorAll('.task-day');
    
    taskDays.forEach(day => {
        const task = day.getAttribute('data-task');
        if (!task) return;
        
        const bubble = document.createElement('div');
        bubble.className = 'task-bubble';
        bubble.innerHTML = `
            <h3>${JSON.parse(task).title}</h3>
            <p>${JSON.parse(task).description}</p>
        `;
        day.appendChild(bubble);
        
        day.addEventListener('mouseenter', (e) => {
            bubble.classList.add('show');
            // Position the bubble above the hovered day
            const rect = day.getBoundingClientRect();
            const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
            const scrollLeft = window.pageXOffset || document.documentElement.scrollLeft;
            
            bubble.style.top = `${rect.top + scrollTop - bubble.offsetHeight - 10}px`;
            bubble.style.left = `${rect.left + scrollLeft + (rect.width - bubble.offsetWidth) / 2}px`;
        });
        
        day.addEventListener('mouseleave', () => {
            bubble.classList.remove('show');
        });
        
        // Update bubble position on scroll
        window.addEventListener('scroll', () => {
            if (bubble.classList.contains('show')) {
                const rect = day.getBoundingClientRect();
                const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
                const scrollLeft = window.pageXOffset || document.documentElement.scrollLeft;
                
                bubble.style.top = `${rect.top + scrollTop - bubble.offsetHeight - 10}px`;
                bubble.style.left = `${rect.left + scrollLeft + (rect.width - bubble.offsetWidth) / 2}px`;
            }
        });
    });
});

function createTaskTooltip(taskDay) {
  const taskData = JSON.parse(taskDay.dataset.tasks);
  const tooltip = document.createElement('div');
  tooltip.className = 'task-tooltip';
  
  const taskList = document.createElement('div');
  taskList.className = 'task-list';
  
  taskData.forEach(task => {
    const taskItem = document.createElement('div');
    taskItem.className = 'task-item';
    
    const taskContent = document.createElement('div');
    taskContent.className = 'task-content';
    
    const taskName = document.createElement('h4');
    taskName.className = 'task-name';
    taskName.textContent = task.task_name;
    
    const taskDescription = document.createElement('p');
    taskDescription.className = 'task-description';
    taskDescription.textContent = task.task_description;
    
    const taskPriority = document.createElement('span');
    taskPriority.className = `task-priority ${task.priority}`;
    taskPriority.textContent = task.priority.charAt(0).toUpperCase() + task.priority.slice(1);
    
    const taskActions = document.createElement('div');
    taskActions.className = 'task-actions';
    
    const editLink = document.createElement('a');
    editLink.href = `edit_task.php?id=${task.id}`;
    editLink.className = 'btn btn-edit';
    editLink.textContent = 'Edit';
    
    taskContent.appendChild(taskName);
    taskContent.appendChild(taskDescription);
    taskContent.appendChild(taskPriority);
    taskActions.appendChild(editLink);
    taskItem.appendChild(taskContent);
    taskItem.appendChild(taskActions);
    taskList.appendChild(taskItem);
  });
  
  tooltip.appendChild(taskList);
  taskDay.appendChild(tooltip);
  
  // ... rest of the existing tooltip code ...
} 