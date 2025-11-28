import React, { useState, useEffect } from 'react';
import { Upload, Plus, Trash2, X } from 'lucide-react'; // Import X icon for removing files

const styles = `
  /* Container for the Achievements page */
  .achievements-container {
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 20px;
    position: relative;
  }

  /* Card container for content */
  .card-container {
    background-color: #fff;
    border-radius: 1rem;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
    width: 100%;
    max-width: 700px;
    margin-top: 4.5rem;
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
    padding-top: 0;
    padding-bottom: 1rem;
  }

  /* Collapsible section header */
  .collapsible-header {
    background-color: #6b48ff;
    color: #fff;
    padding: 10px 15px;
    border-radius: 0.5rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    cursor: pointer;
    font-size: 1.2rem;
    font-weight: 600;
  }

  .collapsible-header:hover {
    background-color: #7c5aff;
  }

  .collapsible-arrow {
    font-size: 1.2rem;
    transition: transform 0.3s ease;
    color: #fff;
  }

  .collapsible-arrow.open {
    transform: rotate(180deg);
  }

  /* Collapsible content (form) */
  .collapsible-content {
    background-color: #fff;
    border: 1px solid #d1d5db;
    border-radius: 0.5rem;
    padding: 1rem;
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  /* Form fields */
  .form-field {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  /* Form field with row layout for labels beside inputs or paired inputs */
  .form-field-row {
    display: flex;
    flex-direction: row;
    align-items: center;
    gap: 1rem;
  }

  /* Date field wrapper for Start Date and End Date */
  .date-field-wrapper {
    display: flex;
    flex-direction: row;
    align-items: center;
    gap: 0.5rem;
    flex: 1;
  }

  /* Add margin-bottom to form-field-row containing date fields */
  .form-field-row.date-row {
    margin-bottom: 1rem;
  }

  .form-label {
    font-size: 1rem;
    font-weight: 600;
    color: #333;
    white-space: nowrap;
  }

  .form-input,
  .form-textarea,
  .form-select {
    padding: 0.75rem;
    border: 1px solid #d1d5db;
    border-radius: 0.5rem;
    font-size: 1rem;
    color: #333;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
    transition: border-color 0.2s, box-shadow 0.2s;
    width: 100%;
  }

  /* Specific widths for "Enter your name" and "Upload your photo" */
  .form-field-row .name-input {
    flex: 0 0 60%;
  }

  .form-field-row .photo-upload {
    flex: 0 0 35%;
  }

  /* Specific widths for "Enter your email" and "Enter your phone number" */
  .form-field-row .email-input {
    flex: 0 0 60%;
  }

  .form-field-row .phone-input {
    flex: 0 0 35%;
  }

  /* Specific widths for "Github URL" and "LinkedIn URL" */
  .form-field-row .github-input {
    flex: 0 0 60%;
  }

  .form-field-row .linkedin-input {
    flex: 0 0 35%;
  }

  /* Specific widths for file upload inputs in various sections */
  .form-field-row .report-upload,
  .form-field-row .competition-upload,
  .form-field-row .internship-upload,
  .form-field-row .course-upload,
  .form-field-row .product-upload,
  .form-field-row .patent-upload,
  .form-field-row .entrepreneurship-upload,
  .form-field-row .placement-upload {
    flex: 0 0 60%;
  }

  /* Style for the status label */
  .status-label {
    color: #ff0000;
    font-size: 1rem;
    font-weight: 600;
    white-space: nowrap;
  }

  /* Specific widths for "Start Date" and "End Date" labels and inputs */
  .form-field-row .start-date-label,
  .form-field-row .end-date-label {
    flex: 0 0 20%;
    text-align: left;
  }

  .form-field-row .start-date-input,
  .form-field-row .end-date-input {
    flex: 0 0 30%;
  }

  .form-textarea {
    resize: vertical;
    min-height: 100px;
  }

  .form-input:focus,
  .form-textarea:focus,
  .form-select:focus {
    outline: none;
    border-color: #6b48ff;
    box-shadow: 0 0 0 3px rgba(107, 72, 255, 0.2);
  }

  /* Custom file input wrapper */
  .file-input-wrapper {
    position: relative;
    display: inline-block;
    width: 100%;
  }

  .file-input-wrapper input[type="file"] {
    width: 100%;
    height: 100%;
    opacity: 0;
    position: absolute;
    top: 0;
    left: 0;
    cursor: pointer;
  }

  .file-input-label {
    display: flex;
    align-items: center;
    padding: 0.75rem;
    border: 1px solid #d1d5db;
    border-radius: 0.5rem;
    font-size: 1rem;
    color: #333;
    background-color: #fff;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
    text-align: left;
    transition: border-color 0.2s, box-shadow 0.2s;
    gap: 0.5rem;
  }

  .file-input-wrapper input[type="file"]:focus + .file-input-label {
    border-color: #6b48ff;
    box-shadow: 0 0 0 3px rgba(107, 72, 255, 0.2);
  }

  /* Style for the upload icon */
  .upload-icon {
    width: 1.2rem;
    height: 1.2rem;
    color: #333;
  }

  /* Generic Add button (used for Add Project, Add Competition, etc.) */
  .add-button {
    display: flex;
    align-items: center;
    background: none;
    border: none;
    padding: 0;
    font-size: 1rem;
    color: #6b48ff;
    cursor: pointer;
    margin-top: 0.5rem;
  }

  .add-button .add-icon {
    display: inline-flex;
    justify-content: center;
    align-items: center;
    width: 1.2rem;
    height: 1.2rem;
    margin-right: 0.5rem;
    background-color: #6b48ff;
    color: #fff;
    border-radius: 50%;
  }

  /* Generic Remove button (used for Remove Project, Remove Competition, etc.) */
  .remove-button {
    display: flex;
    align-items: center;
    background: none;
    border: none;
    padding: 0;
    font-size: 1rem;
    color: #ff0000;
    cursor: pointer;
    margin-bottom: 0.5rem;
  }

  .remove-button .trash-icon {
    display: inline-flex;
    justify-content: center;
    align-items: center;
    width: 1.2rem;
    height: 1.2rem;
    margin-right: 0.5rem;
    background-color: #ff0000;
    color: #fff;
    border-radius: 50%;
  }

  /* Entry container (for visual separation in sections with multiple entries) */
  .entry {
    border-bottom: 1px solid #d1d5db;
    padding-bottom: 1rem;
    margin-bottom: 1rem;
  }

  /* Remove border from the last entry */
  .entry:last-child {
    border-bottom: none;
    padding-bottom: 0;
    margin-bottom: 0;
  }

  /* Add margin-bottom to form fields within entries */
  .entry .form-field {
    margin-bottom: 1rem;
  }

  /* Remove margin-bottom from the last form field in each entry to avoid extra spacing */
  .entry .form-field:last-child {
    margin-bottom: 0;
  }

  /* Uploaded file display */
  .uploaded-file {
    display: flex;
    align-items: center;
    justify-content: space-between;
    background-color: #f9fafb;
    border: 1px solid #e5e7eb;
    border-radius: 0.5rem;
    padding: 0.5rem 1rem;
    margin-top: 0.5rem;
    font-size: 0.9rem;
    color: #374151;
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  /* Remove file button with cross symbol */
  .remove-file-button {
    display: flex;
    align-items: center;
    justify-content: center;
    background-color: #ff4d4f;
    color: #fff;
    border: none;
    border-radius: 50%;
    width: 1.5rem;
    height: 1.5rem;
    cursor: pointer;
    transition: background-color 0.2s ease, transform 0.2s ease;
  }

  .remove-file-button:hover {
    background-color: #e63946;
    transform: scale(1.1);
  }

  .remove-file-button .cross-icon {
    width: 1rem;
    height: 1rem;
  }

  /* Button container for Submit, Preview, and Download */
  .button-container {
    display: flex;
    gap: 1rem;
    justify-content: center;
    margin-top: 1rem;
    flex-wrap: wrap;
  }

  /* Nested container for Preview and Download buttons */
  .secondary-buttons {
    display: flex;
    gap: 1rem;
    justify-content: center;
    flex-wrap: wrap;
  }

  /* Submit button */
  .submit-button {
    background-color: #6b48ff;
    color: #fff;
    padding: 10px 20px;
    border: none;
    border-radius: 0.5rem;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    transition: background-color 0.3s ease;
  }

  .submit-button:hover {
    background-color: #7c5aff;
  }

  /* Preview button */
  .preview-button {
    background-color: #28a745;
    color: #fff;
    padding: 10px 20px;
    border: none;
    border-radius: 0.5rem;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    transition: background-color 0.3s ease;
  }

  .preview-button:hover {
    background-color: #218838;
  }

  /* Download button */
  .download-button {
    background-color: #17a2b8;
    color: #fff;
    padding: 10px 20px;
    border: none;
    border-radius: 0.5rem;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    transition: background-color 0.3s ease;
  }

  .download-button:hover {
    background-color: #138496;
  }

  /* Success Modal */
  .success-modal {
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    background-color: #fff;
    color: #000;
    padding: 1.5rem;
    border-radius: 0.5rem;
    box-shadow: 0 0 15px 5px rgba(107, 72, 255, 0.3),
                0 0 15px 5px rgba(0, 122, 255, 0.3);
    text-align: center;
    z-index: 1000;
    animation: fadeIn 0.3s ease-in-out;
  }

  .success-checkmark {
    font-size: 3rem;
    color: #28a745;
    margin-bottom: 1rem;
    animation: scaleIn 0.5s ease-in-out;
  }

  .success-title {
    font-size: 1.5rem;
    font-weight: 700;
    margin-bottom: 0.5rem;
  }

  .success-message {
    font-size: 1rem;
    font-weight: 400;
    color: #333;
  }

  /* Preview Modal */
  .preview-modal-container {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(0, 0, 0, 0.5);
    display: flex;
    justify-content: center;
    align-items: center;
    z-index: 2000;
  }

  .preview-modal {
    background-color: #fff;
    width: 900px;
    height: 90vh;
    overflow-y: auto;
    border-radius: 0.5rem;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    position: relative;
    padding: 1rem;
  }

  .preview-modal-close {
    position: absolute;
    top: 0.75rem;
    right: 0.75rem;
    background-color: #ff4d4f;
    color: #fff;
    padding: 0.25rem;
    border-radius: 50%;
    cursor: pointer;
    transition: background-color 0.2s, transform 0.2s;
  }

  .preview-modal-close:hover {
    background-color: #e63946;
    transform: scale(1.1);
  }

   /* Resume Template Styles (Modern Professional CV) */
  .resume-container {
    font-family: 'Arial', sans-serif;
    color: #333;
    line-height: 1.8;
    padding: 30px;
    background-color: #fff;
    max-width: 800px;
    margin: 0 auto;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
  }

  .resume-header {
    text-align: center;
    margin-bottom: 2.5rem;
    padding-bottom: 1.5rem;
    border-bottom: 3px solid #005555; /* Teal accent matching PDF */
  }

  .resume-header h1 {
    font-size: 2.4rem;
    font-weight: 700;
    margin: 0;
    color: #005555;
    text-transform: uppercase;
    letter-spacing: 1.5px;
  }

  .resume-header h2 {
    font-size: 1.3rem;
    font-weight: 500;
    margin: 0.6rem 0 0;
    color: #555;
  }

  .resume-photo {
    width: 120px;
    height: 120px;
    border-radius: 50%;
    object-fit: cover;
    border: 3px solid #005555;
    margin: 1.5rem auto;
    display: block;
  }

  .resume-contact {
    display: flex;
    flex-wrap: wrap;
    gap: 1.5rem;
    justify-content: center;
    margin-bottom: 1.5rem;
  }

  .resume-contact p {
    font-size: 0.95rem;
    margin: 0;
    color: #444;
  }

  .resume-section {
    margin-bottom: 2rem;
  }

  .resume-section h3 {
    font-size: 1.6rem;
    font-weight: 600;
    color: #005555;
    text-transform: uppercase;
    margin-bottom: 1.2rem;
    border-bottom: 2px solid #e0e0e0;
    padding-bottom: 0.6rem;
  }

  .resume-section h4 {
    font-size: 1.25rem;
    font-weight: 600;
    margin: 0.6rem 0;
    color: #333;
  }

  .resume-section p {
    font-size: 0.95rem;
    margin: 0.4rem 0;
    color: #444;
  }

  .resume-section ul {
    list-style-type: disc;
    margin-left: 25px;
    padding-left: 10px;
  }

  .resume-section ul li {
    font-size: 0.95rem;
    margin-bottom: 0.6rem;
    color: #444;
  }

  .resume-item {
    margin-bottom: 1.5rem;
  }

  /* Animations */
  @keyframes fadeIn {
    from {
      opacity: 0;
      transform: translate(-50%, -60%);
    }
    to {
      opacity: 1;
      transform: translate(-50%, -50%);
    }
  }

  @keyframes scaleIn {
    from {
      transform: scale(0);
    }
    to {
      transform: scale(1);
    }
  }

  /* Responsive adjustments */
  @media (max-width: 768px) {
    .achievements-container {
      padding: 8px;
    }

    .card-container {
      // padding: 0.75rem;
      margin-top: 4.5rem;
      padding-top: 0;
      padding-bottom: 0.75rem;
      gap: 0.5rem;
    }

    .collapsible-header {
      padding: 8px 12px;
      font-size: 1rem;
    }

    .collapsible-arrow {
      font-size: 1rem;
    }

    .collapsible-content {
      padding: 0.75rem;
      gap: 0.5rem;
    }

    .form-field-row {
      flex-direction: column;
      align-items: flex-start;
      gap: 0.5rem;
    }

    .form-field-row.date-row {
      margin-bottom: 0.75rem;
    }

    .date-field-wrapper {
      flex-direction: column;
      align-items: flex-start;
      width: 100%;
    }

    .form-field-row .report-upload,
    .form-field-row .competition-upload,
    .form-field-row .internship-upload,
    .form-field-row .course-upload,
    .form-field-row .product-upload,
    .form-field-row .patent-upload,
    .form-field-row .entrepreneurship-upload,
    .form-field-row .placement-upload {
      flex: 1;
      width: 100%;
    }

    .form-field-row .name-input,
    .form-field-row .photo-upload,
    .form-field-row .email-input,
    .form-field-row .phone-input,
    .form-field-row .github-input,
    .form-field-row .linkedin-input {
      flex: 1;
      width: 100%;
    }

    .form-field-row .status-label {
      font-size: 0.9rem;
    }

    .form-input,
    .form-textarea,
    .form-select {
      padding: 0.5rem;
      font-size: 0.9rem;
    }

    .form-field-row .start-date-input,
    .form-field-row .end-date-input {
      flex: 1;
      width: 100%;
    }

    .form-field-row .start-date-label,
    .form-field-row .end-date-label {
      flex: 1;
      width: 100%;
    }

    .form-textarea {
      min-height: 80px;
    }

    .file-input-label {
      padding: 0.5rem;
      font-size: 0.9rem;
      gap: 0.4rem;
    }

    .upload-icon {
      width: 1rem;
      height: 1rem;
    }

    .form-label {
      font-size: 0.9rem;
    }

    .add-button,
    .remove-button {
      font-size: 0.9rem;
    }

    .add-button .add-icon,
    .remove-button .trash-icon {
      width: 1rem;
      height: 1rem;
      margin-right: 0.4rem;
    }

    .entry .form-field {
      margin-bottom: 0.75rem;
    }

    .remove-button {
      margin-bottom: 0.4rem;
    }

    /* Updated button layout for mobile */
    .button-container {
      flex-direction: column;
      align-items: center;
      gap: 0.5rem;
    }

    .submit-button {
      padding: 8px 16px;
      font-size: 0.9rem;
      width: 100%;
      max-width: 200px;
    }

    .secondary-buttons {
      flex-direction: row;
      gap: 0.5rem;
    }

    .preview-button,
    .download-button {
      padding: 8px 16px;
      font-size: 0.9rem;
      width: 100%;
      max-width: 100px; /* Reduced width for side-by-side layout */
    }

    .preview-modal {
      width: 90%;
      height: 90vh;
      padding: 0.5rem;
    }

    .resume-container {
      padding: 15px;
    }

    .resume-header h1 {
      font-size: 1.9rem;
    }

    .resume-header h2 {
      font-size: 1.1rem;
    }

    .resume-photo {
      width: 90px;
      height: 90px;
    }

    .resume-contact {
      flex-direction: column;
      align-items: center;
      gap: 0.8rem;
    }

    .resume-section h3 {
      font-size: 1.3rem;
    }

    .resume-section h4 {
      font-size: 1.1rem;
    }

    .resume-section p,
    .resume-section ul li {
      font-size: 0.9rem;
    }

    .uploaded-file {
      font-size: 0.8rem;
      padding: 0.4rem 0.8rem;
    }

    .remove-file-button {
      width: 1.2rem;
      height: 1.2rem;
    }

    .remove-file-button .cross-icon {
      width: 0.8rem;
      height: 0.8rem;
    }
  }
`;

const Achievements = () => {
  const [formData, setFormData] = useState({
    personalDetails: {
      name: '',
      photo: null,
      email: '',
      phoneNumber: '',
      githubUrl: '',
      linkedinUrl: '',
    },
    profileSummary: {
      description: '',
    },
    academicDetails: [
      {
        institutionName: '',
        yearOfPassing: '',
        percentage: '',
        degreeOrClass: '',
      },
    ],
    skills: {
      skills: '',
      areaOfInterest: '',
    },
    paperPresentations: [
      {
        title: '',
        startDate: '',
        endDate: '',
        description: '',
        collegeName: '',
        conferenceName: '',
        proof: null,
      },
    ],
    publications: [
      {
        title: '',
        journalName: '',
        category: '',
        startDate: '',
        endDate: '',
        proof: null,
      },
    ],
    patents: [
      {
        title: '',
        startDate: '',
        endDate: '',
        proof: null,
      },
    ],
    entrepreneurship: [
      {
        title: '',
        companyName: '',
        website: '',
        proof: null,
        product: '',
      },
    ],
    placement: [
      {
        companyName: '',
        salary: '',
        proof: null,
        dateOfPlacement: '',
      },
    ],
    projectDetails: [
      {
        title: '',
        url: '',
        document: null,
        description: '',
        startDate: '',
        endDate: '',
      },
    ],
    competitions: [
      {
        title: '',
        organizer: '',
        winningDetails: '',
        startDate: '',
        endDate: '',
        upload: null,
        description: '',
      },
    ],
    internship: [
      {
        companyName: '',
        role: '',
        startDate: '',
        endDate: '',
        certificate: null,
        description: '',
      },
    ],
    onlineCourse: [
      {
        courseName: '',
        startDate: '',
        endDate: '',
        certifications: null,
        description: '',
      },
    ],
    productDevelopment: [
      {
        productName: '',
        details: '',
        startDate: '',
        endDate: '',
        upload: null,
      },
    ],
    languages: {
      language: '',
      level: '',
    },
  });

  const [openSection, setOpenSection] = useState(null);
  const [showSuccess, setShowSuccess] = useState(false);
  const [showPreview, setShowPreview] = useState(false);

  // Fetch data on mount
  useEffect(() => {
  const userEmail = localStorage.getItem('email'); // Use email as userEmail
  if (!userEmail) return;
  fetch(`http://localhost:8000/api/achievements?userEmail=${encodeURIComponent(userEmail)}`)
    .then(res => res.json())
    .then(data => {
      if (data && data.achievement) {
        setFormData(prev => deepMerge(prev, data.achievement));
      }
    });
}, []);

  // Helper function for deep merge
  function deepMerge(target, source) {
    for (const key in source) {
      if (
        source[key] &&
        typeof source[key] === 'object' &&
        !Array.isArray(source[key])
      ) {
        target[key] = deepMerge({ ...(target[key] || {}) }, source[key]);
      } else if (Array.isArray(source[key])) {
        target[key] = source[key];
      } else {
        target[key] = source[key];
      }
    }
    return { ...target };
  }

  const toggleSection = (section) => {
    setOpenSection(openSection === section ? null : section);
  };

  const handleInputChange = (section, field, value, index = null) => {
    if (index !== null) {
      setFormData((prev) => {
        const updatedEntries = [...prev[section]];
        updatedEntries[index] = {
          ...updatedEntries[index],
          [field]: value,
        };
        return {
          ...prev,
          [section]: updatedEntries,
        };
      });
    } else {
      setFormData((prev) => ({
        ...prev,
        [section]: {
          ...prev[section],
          [field]: value,
        },
      }));
    }
  };

  const handleFileChange = (section, field, event, index = null) => {
    const file = event.target.files[0];
    if (index !== null) {
      setFormData((prev) => {
        const updatedEntries = [...prev[section]];
        updatedEntries[index] = {
          ...updatedEntries[index],
          [field]: file,
        };
        return {
          ...prev,
          [section]: updatedEntries,
        };
      });
    } else {
      setFormData((prev) => ({
        ...prev,
        [section]: {
          ...prev[section],
          [field]: file,
        },
      }));
    }
  };

  const removeFile = (section, field, index = null) => {
    if (index !== null) {
      setFormData((prev) => {
        const updatedEntries = [...prev[section]];
        updatedEntries[index] = {
          ...updatedEntries[index],
          [field]: null,
        };
        return {
          ...prev,
          [section]: updatedEntries,
        };
      });
    } else {
      setFormData((prev) => ({
        ...prev,
        [section]: {
          ...prev[section],
          [field]: null,
        },
      }));
    }
  };

  const addEntry = (section, initialEntry) => {
    setFormData((prev) => ({
      ...prev,
      [section]: [...prev[section], initialEntry],
    }));
  };

  const removeEntry = (section, index) => {
    setFormData((prev) => ({
      ...prev,
      [section]: prev[section].filter((_, i) => i !== index),
    }));
  };

  const addAcademicDetail = () => {
    addEntry('academicDetails', {
      institutionName: '',
      yearOfPassing: '',
      percentage: '',
      degreeOrClass: '',
    });
  };

  // Generic async remove function for array sections
const removeSectionEntry = async (section, index) => {
  const userEmail = localStorage.getItem('email');
  if (!userEmail) return;
  const res = await fetch(
    `http://localhost:8000/api/achievements/${encodeURIComponent(userEmail)}/${section}/${index}`,
    { method: 'DELETE' }
  );
  if (res.ok) {
    removeEntry(section, index);
  } else {
    alert(`Failed to delete entry from ${section}`);
  }
};

  const removeAcademicDetail = (index) => removeSectionEntry('academicDetails', index);
  const removePaperPresentation = (index) => removeSectionEntry('paperPresentations', index);
  const removePublication = (index) => removeSectionEntry('publications', index);
  const removePatent = (index) => removeSectionEntry('patents', index);
  const removeEntrepreneurship = (index) => removeSectionEntry('entrepreneurship', index);
  const removePlacement = (index) => removeSectionEntry('placement', index);
  const removeProject = (index) => removeSectionEntry('projectDetails', index);
  const removeCompetition = (index) => removeSectionEntry('competitions', index);
  const removeInternship = (index) => removeSectionEntry('internship', index);
  const removeOnlineCourse = (index) => removeSectionEntry('onlineCourse', index);
  const removeProductDevelopment = (index) => removeSectionEntry('productDevelopment', index);

  const addPaperPresentation = () => {
    addEntry('paperPresentations', {
      title: '',
      startDate: '',
      endDate: '',
      description: '',
      collegeName: '',
      conferenceName: '',
      proof: null,
    });
  };

  const addPublication = () => {
    addEntry('publications', {
      title: '',
      journalName: '',
      category: '',
      startDate: '',
      endDate: '',
      proof: null,
    });
  };

  const addPatent = () => {
    addEntry('patents', {
      title: '',
      startDate: '',
      endDate: '',
      proof: null,
    });
  };

  const addEntrepreneurship = () => {
    addEntry('entrepreneurship', {
      title: '',
      companyName: '',
      website: '',
      proof: null,
      product: '',
    });
  };

  const addPlacement = () => {
    addEntry('placement', {
      companyName: '',
      salary: '',
      proof: null,
      dateOfPlacement: '',
    });
  };

  const addProject = () => {
    addEntry('projectDetails', {
      title: '',
      url: '',
      document: null,
      description: '',
      startDate: '',
      endDate: '',
    });
  };

  const addCompetition = () => {
    addEntry('competitions', {
      title: '',
      organizer: '',
      winningDetails: '',
      startDate: '',
      endDate: '',
      upload: null,
      description: '',
    });
  };

  const addInternship = () => {
    addEntry('internship', {
      companyName: '',
      role: '',
      startDate: '',
      endDate: '',
      certificate: null,
      description: '',
    });
  };

  const addOnlineCourse = () => {
    addEntry('onlineCourse', {
      courseName: '',
      startDate: '',
      endDate: '',
      certifications: null,
      description: '',
    });
  };

  const addProductDevelopment = () => {
    addEntry('productDevelopment', {
      productName: '',
      details: '',
      startDate: '',
      endDate: '',
      upload: null,
    });
  };

  function cleanFormData(data) {
    const cleaned = {};
    for (const key in data) {
      if (Array.isArray(data[key])) {
        // Remove empty objects from arrays
        const arr = data[key].filter(item =>
          Object.values(item).some(val => val !== '' && val !== null)
        );
        if (arr.length > 0) cleaned[key] = arr;
      } else if (typeof data[key] === 'object' && data[key] !== null) {
        // Remove empty fields from objects
        const obj = {};
        for (const k in data[key]) {
          if (data[key][k] !== '' && data[key][k] !== null) obj[k] = data[key][k];
        }
        if (Object.keys(obj).length > 0) cleaned[key] = obj;
      } else if (data[key] !== '' && data[key] !== null) {
        cleaned[key] = data[key];
      }
    }
    return cleaned;
  }

const handleSubmit = async () => {
  const userEmail = localStorage.getItem('email');
  if (!userEmail) {
    alert('User not logged in');
    return;
  }
  // Clean the form data before sending
  const cleanedData = cleanFormData(formData);
  const data = { userEmail, ...cleanedData };
  const response = await fetch('http://localhost:8000/api/achievements', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (response.ok) {
    setShowSuccess(true);
    setTimeout(() => setShowSuccess(false), 2000);
  } else {
    alert('Failed to submit achievements');
  }
};

  const handlePreview = () => {
    setShowPreview(true);
  };

  const handleClosePreview = () => {
    setShowPreview(false);
  };

  const handleDownload = () => {
    const element = document.getElementById('resume-preview');
    const opt = {
      margin: 0.5,
      filename: 'resume.pdf',
      image: { type: 'jpeg', quality: 0.98 },
      html2canvas: { scale: 2 },
      jsPDF: { unit: 'in', format: 'letter', orientation: 'portrait' }
    };
    window.html2pdf().set(opt).from(element).save();
  };

  const photoUrl = formData.personalDetails.photo ? URL.createObjectURL(formData.personalDetails.photo) : null;

  const skills = formData.skills.skills ? formData.skills.skills.split(',').map(skill => skill.trim()) : [];
  const languages = formData.languages.language ? formData.languages.language.split(',').map(lang => lang.trim()) : [];

  // When user edits and clicks "Save"
const handleSave = async () => {
  const userEmail = localStorage.getItem('email');
  // Collect all updated fields in 'data'
  const data = { userEmail, ...allAchievementFields }; // allAchievementFields = your state
  await fetch('http://localhost:8000/api/achievements', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
};

  return (
    <>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js"></script>
      <style>{styles}</style>
      <div className="achievements-container">
        <div className="card-container">
          {/* From these onwards the form section begins*/}
          
          <div></div>
          {/* Personal Details Section */}
          <div>
            <div className="collapsible-header" onClick={() => toggleSection('personalDetails')}>
              <span>Personal Details</span>
              <span className={`collapsible-arrow ${openSection === 'personalDetails' ? 'open' : ''}`}>
                ▼
              </span>
            </div>
            {openSection === 'personalDetails' && (
              <div className="collapsible-content">
                <div className="form-field-row">
                  <div className="form-field name-input">
                    <input
                      type="text"
                      className="form-input"
                      placeholder="Enter your name"
                      value={formData.personalDetails.name}
                      onChange={(e) => handleInputChange('personalDetails', 'name', e.target.value)}
                      required
                    />
                  </div>
                  <div className="form-field file-input-wrapper photo-upload">
                    <input
                      type="file"
                      className="form-input"
                      accept="image/*"
                      onChange={(e) => handleFileChange('personalDetails', 'photo', e)}
                      required
                    />
                    <span className="file-input-label">
                      <Upload className="upload-icon" />
                      Upload photo
                    </span>
                  </div>
                </div>
                {formData.personalDetails.photo && (
                  <div className="uploaded-file">
                    <span>{formData.personalDetails.photo.name}</span>
                    <button
                      className="remove-file-button"
                      onClick={() => removeFile('personalDetails', 'photo')}
                    >
                      <X className="cross-icon" />
                    </button>
                  </div>
                )}
                <div className="form-field-row">
                  <div className="form-field email-input">
                    <input
                      type="email"
                      className="form-input"
                      placeholder="Enter your email"
                      value={formData.personalDetails.email}
                      onChange={(e) => handleInputChange('personalDetails', 'email', e.target.value)}
                      required
                    />
                  </div>
                  <div className="form-field phone-input">
                    <input
                      type="tel"
                      className="form-input"
                      placeholder="Enter phone number"
                      value={formData.personalDetails.phoneNumber}
                      onChange={(e) => handleInputChange('personalDetails', 'phoneNumber', e.target.value)}
                      required
                    />
                  </div>
                </div>
                <div className="form-field-row">
                  <div className="form-field github-input">
                    <input
                      type="url"
                      className="form-input"
                      placeholder="Enter your Github URL"
                      value={formData.personalDetails.githubUrl}
                      onChange={(e) => handleInputChange('personalDetails', 'githubUrl', e.target.value)}
                      required
                    />
                  </div>
                  <div className="form-field linkedin-input">
                    <input
                      type="url"
                      className="form-input"
                      placeholder="Enter LinkedIn URL"
                      value={formData.personalDetails.linkedinUrl}
                      onChange={(e) => handleInputChange('personalDetails', 'linkedinUrl', e.target.value)}
                      required
                    />
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Profile Summary Section */}
          <div>
            <div className="collapsible-header" onClick={() => toggleSection('profileSummary')}>
              <span>Profile Summary</span>
              <span className={`collapsible-arrow ${openSection === 'profileSummary' ? 'open' : ''}`}>
                ▼
              </span>
            </div>
            {openSection === 'profileSummary' && (
              <div className="collapsible-content">
                <div className="form-field">
                  <textarea
                    className="form-textarea"
                    placeholder="Enter your profile summary "
                    value={formData.profileSummary.description}
                    onChange={(e) => handleInputChange('profileSummary', 'description', e.target.value)}
                    required
                  />
                </div>
              </div>
            )}
          </div>

          {/* Academic Details Section */}
          <div>
            <div className="collapsible-header" onClick={() => toggleSection('academicDetails')}>
              <span>Academic Details</span>
              <span className={`collapsible-arrow ${openSection === 'academicDetails' ? 'open' : ''}`}>
                ▼
              </span>
            </div>
            {openSection === 'academicDetails' && (
              <div className="collapsible-content">
                {formData.academicDetails.map((academic, index) => (
                  <div key={index} className="entry">
                    {formData.academicDetails.length > 1 && (
                      <button className="remove-button" onClick={() => removeAcademicDetail(index)}>
                        <Trash2 className="trash-icon" />
                        Remove Academic Detail
                      </button>
                    )}
                    <div className="form-field">
                      <input
                        type="text"
                        className="form-input"
                        placeholder="Enter name of the institution"
                        value={academic.institutionName}
                        onChange={(e) => handleInputChange('academicDetails', 'institutionName', e.target.value, index)}
                        required
                      />
                    </div>
                    <div className="form-field">
                      <input
                        type="text"
                        className="form-input"
                        placeholder="Enter degree or class (e.g., B.Tech, Class XII)"
                        value={academic.degreeOrClass}
                        onChange={(e) => handleInputChange('academicDetails', 'degreeOrClass', e.target.value, index)}
                        required
                      />
                    </div>
                    <div className="form-field">
                      <input
                        type="number"
                        className="form-input"
                        placeholder="Enter year of passing"
                        value={academic.yearOfPassing}
                        onChange={(e) => handleInputChange('academicDetails', 'yearOfPassing', e.target.value, index)}
                        required
                      />
                    </div>
                    <div className="form-field">
                      <input
                        type="number"
                        className="form-input"
                        placeholder="Enter percentage"
                        step="0.1"
                        min="0"
                        max="100"
                        value={academic.percentage}
                        onChange={(e) => handleInputChange('academicDetails', 'percentage', e.target.value, index)}
                        required
                      />
                    </div>
                  </div>
                ))}
                <button className="add-button" onClick={addAcademicDetail}>
                  <Plus className="add-icon" />
                  Add Academic Detail
                </button>
              </div>
            )}
          </div>

          {/* Skills Section */}
          <div>
            <div className="collapsible-header" onClick={() => toggleSection('skills')}>
              <span>Skills</span>
              <span className={`collapsible-arrow ${openSection === 'skills' ? 'open' : ''}`}>
                ▼
              </span>
            </div>
            {openSection === 'skills' && (
              <div className="collapsible-content">
                <div className="form-field">
                  <input
                    type="text"
                    className="form-input"
                    placeholder="Enter your skills (e.g., JavaScript, React)"
                    value={formData.skills.skills}
                    onChange={(e) => handleInputChange('skills', 'skills', e.target.value)}
                    required
                  />
                </div>
                <div className="form-field">
                  <input
                    type="text"
                    className="form-input"
                    placeholder="Enter your area of interest (e.g., Full-stack, Embedded)"
                    value={formData.skills.areaOfInterest}
                    onChange={(e) => handleInputChange('skills', 'areaOfInterest', e.target.value)}
                    required
                  />
                </div>
              </div>
            )}
          </div>

          {/* Paper Presentation Section */}
          <div>
            <div className="collapsible-header" onClick={() => toggleSection('paperPresentations')}>
              <span>Paper Presentations</span>
              <span className={`collapsible-arrow ${openSection === 'paperPresentations' ? 'open' : ''}`}>
                ▼
              </span>
            </div>
            {openSection === 'paperPresentations' && (
              <div className="collapsible-content">
                {formData.paperPresentations.map((presentation, index) => (
                  <div key={index} className="entry">
                    {formData.paperPresentations.length > 1 && (
                      <button className="remove-button" onClick={() => removePaperPresentation(index)}>
                        <Trash2 className="trash-icon" />
                        Remove Paper Presentation
                      </button>
                    )}
                    <div className="form-field">
                      <input
                        type="text"
                        className="form-input"
                        placeholder="Enter presentation title"
                        value={presentation.title}
                        onChange={(e) => handleInputChange('paperPresentations', 'title', e.target.value, index)}
                        required
                      />
                    </div>
                    <div className="form-field-row date-row">
                      <div className="date-field-wrapper">
                        <label htmlFor={"paper-presentation-start-date-" + index} className="form-label start-date-label">Start Date:</label>
                        <div className="form-field start-date-input">
                          <input
                            type="date"
                            id={"paper-presentation-start-date-" + index}
                            className="form-input"
                            placeholder="Select start date"
                            value={presentation.startDate}
                            onChange={(e) => handleInputChange('paperPresentations', 'startDate', e.target.value, index)}
                            required
                          />
                        </div>
                      </div>
                      <div className="date-field-wrapper">
                        <label htmlFor={"paper-presentation-end-date-" + index} className="form-label end-date-label">End Date:</label>
                        <div className="form-field end-date-input">
                          <input
                            type="date"
                            id={"paper-presentation-end-date-" + index}
                            className="form-input"
                            placeholder="Select end date"
                            value={presentation.endDate}
                            onChange={(e) => handleInputChange('paperPresentations', 'endDate', e.target.value, index)}
                            required
                          />
                        </div>
                      </div>
                    </div>
                    <div className="form-field">
                      <textarea
                        className="form-textarea"
                        placeholder="Enter presentation description"
                        value={presentation.description}
                        onChange={(e) => handleInputChange('paperPresentations', 'description', e.target.value, index)}
                        required
                      />
                    </div>
                    <div className="form-field">
                      <input
                        type="text"
                        className="form-input"
                        placeholder="Enter college name"
                        value={presentation.collegeName}
                        onChange={(e) => handleInputChange('paperPresentations', 'collegeName', e.target.value, index)}
                        required
                      />
                    </div>
                    <div className="form-field">
                      <input
                        type="text"
                        className="form-input"
                        placeholder="Enter conference name"
                        value={presentation.conferenceName}
                        onChange={(e) => handleInputChange('paperPresentations', 'conferenceName', e.target.value, index)}
                        required
                      />
                    </div>
                    <div className="form-field-row">
                      <div className="form-field file-input-wrapper presentation-upload">
                        <input
                          type="file"
                          className="form-input"
                          accept=".pdf,.jpg,.png"
                          onChange={(e) => handleFileChange('paperPresentations', 'proof', e, index)}
                          required
                        />
                        <span className="file-input-label">
                          <Upload className="upload-icon" />
                          Upload paper
                        </span>
                      </div>
                      <span className="status-label">Status: Pending</span>
                    </div>
                    {presentation.proof && (
                      <div className="uploaded-file">
                        <span>{presentation.proof.name}</span>
                        <button
                          className="remove-file-button"
                          onClick={() => removeFile('paperPresentations', 'proof', index)}
                        >
                          <X className="cross-icon" />
                        </button>
                      </div>
                    )}
                  </div>
                ))}
                <button className="add-button" onClick={addPaperPresentation}>
                  <Plus className="add-icon" />
                  Add Paper Presentation
                </button>
              </div>
            )}
          </div>

          {/* Publication Section */}
          <div>
            <div className="collapsible-header" onClick={() => toggleSection('publications')}>
              <span>Publications</span>
              <span className={`collapsible-arrow ${openSection === 'publications' ? 'open' : ''}`}>
                ▼
              </span>
            </div>
            {openSection === 'publications' && (
              <div className="collapsible-content">
                {formData.publications.map((publication, index) => (
                  <div key={index} className="entry">
                    {formData.publications.length > 1 && (
                      <button className="remove-button" onClick={() => removePublication(index)}>
                        <Trash2 className="trash-icon" />
                        Remove Publication
                      </button>
                    )}
                    <div className="form-field">
                      <input
                        type="text"
                        className="form-input"
                        placeholder="Enter publication title"
                        value={publication.title}
                        onChange={(e) => handleInputChange('publications', 'title', e.target.value, index)}
                        required
                      />
                    </div>
                    <div className="form-field">
                      <input
                        type="text"
                        className="form-input"
                        placeholder="Enter journal name"
                        value={publication.journalName}
                        onChange={(e) => handleInputChange('publications', 'journalName', e.target.value, index)}
                        required
                      />
                    </div>
                    <div className="form-field">
                      <input
                        type="text"
                        className="form-input"
                        placeholder="Enter category"
                        value={publication.category}
                        onChange={(e) => handleInputChange('publications', 'category', e.target.value, index)}
                        required
                      />
                    </div>
                    <div className="form-field-row date-row">
                      <div className="date-field-wrapper">
                        <label htmlFor={"publication-start-date-" + index} className="form-label start-date-label">Start Date:</label>
                        <div className="form-field start-date-input">
                          <input
                            type="date"
                            id={"publication-start-date-" + index}
                            className="form-input"
                            placeholder="Select start date"
                            value={publication.startDate}
                            onChange={(e) => handleInputChange('publications', 'startDate', e.target.value, index)}
                            required
                          />
                        </div>
                      </div>
                      <div className="date-field-wrapper">
                        <label htmlFor={"publication-end-date-" + index} className="form-label end-date-label">End Date:</label>
                        <div className="form-field end-date-input">
                          <input
                            type="date"
                            id={"publication-end-date-" + index}
                            className="form-input"
                            placeholder="Select end date"
                            value={publication.endDate}
                            onChange={(e) => handleInputChange('publications', 'endDate', e.target.value, index)}
                            required
                          />
                        </div>
                      </div>
                    </div>
                    <div className="form-field-row">
                      <div className="form-field file-input-wrapper publication-upload">
                        <input
                          type="file"
                          className="form-input"
                          accept=".pdf,.jpg,.png"
                          onChange={(e) => handleFileChange('publications', 'proof', e, index)}
                          required
                        />
                        <span className="file-input-label">
                          <Upload className="upload-icon" />
                          Upload paper
                        </span>
                      </div>
                      <span className="status-label">Status: Pending</span>
                    </div>
                    {publication.proof && (
                      <div className="uploaded-file">
                        <span>{publication.proof.name}</span>
                        <button
                          className="remove-file-button"
                          onClick={() => removeFile('publications', 'proof', index)}
                        >
                          <X className="cross-icon" />
                        </button>
                      </div>
                    )}
                  </div>
                ))}
                <button className="add-button" onClick={addPublication}>
                  <Plus className="add-icon" />
                  Add Publication
                </button>
              </div>
            )}
          </div>

          {/* Patent Section */}
          <div>
            <div className="collapsible-header" onClick={() => toggleSection('patents')}>
              <span>Patents</span>
              <span className={`collapsible-arrow ${openSection === 'patents' ? 'open' : ''}`}>
                ▼
              </span>
            </div>
            {openSection === 'patents' && (
              <div className="collapsible-content">
                {formData.patents.map((patent, index) => (
                  <div key={index} className="entry">
                    {formData.patents.length > 1 && (
                      <button className="remove-button" onClick={() => removePatent(index)}>
                        <Trash2 className="trash-icon" />
                        Remove Patent
                      </button>
                    )}
                    <div className="form-field">
                      <input
                        type="text"
                        className="form-input"
                        placeholder="Enter patent title"
                        value={patent.title}
                        onChange={(e) => handleInputChange('patents', 'title', e.target.value, index)}
                        required
                      />
                    </div>
                    <div className="form-field-row date-row">
                      <div className="date-field-wrapper">
                        <label htmlFor={"patent-start-date-" + index} className="form-label start-date-label">Start Date:</label>
                        <div className="form-field start-date-input">
                          <input
                            type="date"
                            id={"patent-start-date-" + index}
                            className="form-input"
                            placeholder="Select start date"
                            value={patent.startDate}
                            onChange={(e) => handleInputChange('patents', 'startDate', e.target.value, index)}
                            required
                          />
                        </div>
                      </div>
                      <div className="date-field-wrapper">
                        <label htmlFor={"patent-end-date-" + index} className="form-label end-date-label">End Date:</label>
                        <div className="form-field end-date-input">
                          <input
                            type="date"
                            id={"patent-end-date-" + index}
                            className="form-input"
                            placeholder="Select end date"
                            value={patent.endDate}
                            onChange={(e) => handleInputChange('patents', 'endDate', e.target.value, index)}
                            required
                          />
                        </div>
                      </div>
                    </div>
                    <div className="form-field-row">
                      <div className="form-field file-input-wrapper patent-upload">
                        <input
                          type="file"
                          className="form-input"
                          accept=".pdf,.jpg,.png"
                          onChange={(e) => handleFileChange('patents', 'proof', e, index)}
                          required
                        />
                        <span className="file-input-label">
                          <Upload className="upload-icon" />
                          Upload proof
                        </span>
                      </div>
                      <span className="status-label">Status: Pending</span>
                    </div>
                    {patent.proof && (
                      <div className="uploaded-file">
                        <span>{patent.proof.name}</span>
                        <button
                          className="remove-file-button"
                          onClick={() => removeFile('patents', 'proof', index)}
                        >
                          <X className="cross-icon" />
                        </button>
                      </div>
                    )}
                  </div>
                ))}
                <button className="add-button" onClick={addPatent}>
                  <Plus className="add-icon" />
                  Add Patent
                </button>
              </div>
            )}
          </div>

          {/* Entrepreneurship Section */}
          <div>
            <div className="collapsible-header" onClick={() => toggleSection('entrepreneurship')}>
              <span>Entrepreneurship</span>
              <span className={`collapsible-arrow ${openSection === 'entrepreneurship' ? 'open' : ''}`}>
                ▼
              </span>
            </div>
            {openSection === 'entrepreneurship' && (
              <div className="collapsible-content">
                {formData.entrepreneurship.map((entry, index) => (
                  <div key={index} className="entry">
                    {formData.entrepreneurship.length > 1 && (
                      <button className="remove-button" onClick={() => removeEntrepreneurship(index)}>
                        <Trash2 className="trash-icon" />
                        Remove Entrepreneurship Entry
                      </button>
                    )}
                    <div className="form-field">
                      <input
                        type="text"
                        className="form-input"
                        placeholder="Enter entrepreneurship title"
                        value={entry.title}
                        onChange={(e) => handleInputChange('entrepreneurship', 'title', e.target.value, index)}
                        required
                      />
                    </div>
                    <div className="form-field">
                      <input
                        type="text"
                        className="form-input"
                        placeholder="Enter company name"
                        value={entry.companyName}
                        onChange={(e) => handleInputChange('entrepreneurship', 'companyName', e.target.value, index)}
                        required
                      />
                    </div>
                    <div className="form-field">
                      <input
                        type="url"
                        className="form-input"
                        placeholder="Enter website URL"
                        value={entry.website}
                        onChange={(e) => handleInputChange('entrepreneurship', 'website', e.target.value, index)}
                        required
                      />
                    </div>
                    <div className="form-field-row">
                      <div className="form-field file-input-wrapper entrepreneurship-upload">
                        <input
                          type="file"
                          className="form-input"
                          accept=".pdf,.jpg,.png"
                          onChange={(e) => handleFileChange('entrepreneurship', 'proof', e, index)}
                          required
                        />
                        <span className="file-input-label">
                          <Upload className="upload-icon" />
                          Upload proof
                        </span>
                      </div>
                      <span className="status-label">Status: Pending</span>
                    </div>
                    {entry.proof && (
                      <div className="uploaded-file">
                        <span>{entry.proof.name}</span>
                        <button
                          className="remove-file-button"
                          onClick={() => removeFile('entrepreneurship', 'proof', index)}
                        >
                          <X className="cross-icon" />
                        </button>
                      </div>
                    )}
                    <div className="form-field">
                      <input
                        type="text"
                        className="form-input"
                        placeholder="Enter product name"
                        value={entry.product}
                        onChange={(e) => handleInputChange('entrepreneurship', 'product', e.target.value, index)}
                        required
                      />
                    </div>
                  </div>
                ))}
                <button className="add-button" onClick={addEntrepreneurship}>
                  <Plus className="add-icon" />
                  Add Entrepreneurship Entry
                </button>
              </div>
            )}
          </div>

          {/* Placement Section */}
          <div>
            <div className="collapsible-header" onClick={() => toggleSection('placement')}>
              <span>Placement</span>
              <span className={`collapsible-arrow ${openSection === 'placement' ? 'open' : ''}`}>
                ▼
              </span>
            </div>
            {openSection === 'placement' && (
              <div className="collapsible-content">
                {formData.placement.map((placement, index) => (
                  <div key={index} className="entry">
                    {formData.placement.length > 1 && (
                      <button className="remove-button" onClick={() => removePlacement(index)}>
                        <Trash2 className="trash-icon" />
                        Remove Placement
                      </button>
                    )}
                    <div className="form-field">
                      <input
                        type="text"
                        className="form-input"
                        placeholder="Enter company name"
                        value={placement.companyName}
                        onChange={(e) => handleInputChange('placement', 'companyName', e.target.value, index)}
                        required
                      />
                    </div>
                    <div className="form-field">
                      <input
                        type="number"
                        className="form-input"
                        placeholder="Enter salary"
                        value={placement.salary}
                        onChange={(e) => handleInputChange('placement', 'salary', e.target.value, index)}
                        required
                      />
                    </div>
                    <div className="form-field-row">
                      <div className="form-field file-input-wrapper placement-upload">
                        <input
                          type="file"
                          className="form-input"
                          accept=".pdf,.jpg,.png"
                          onChange={(e) => handleFileChange('placement', 'proof', e, index)}
                          required
                        />
                        <span className="file-input-label">
                          <Upload className="upload-icon" />
                          Upload Offer letter
                        </span>
                        
                      </div>
                      <span className="status-label">Status: Pending</span>
                    </div>
                    {placement.proof && (
                      <div className="uploaded-file">
                        <span>{placement.proof.name}</span>
                        <button
                          className="remove-file-button"
                          onClick={() => removeFile('placement', 'proof', index)}
                        >
                          <X className="cross-icon" />
                        </button>
                      </div>
                    )}
                    <div className="form-field">
                      <label htmlFor={"placement-date-" + index} className="form-label">Date of Placement:</label>
                      <input
                        type="date"
                        id={"placement-date-" + index}
                        className="form-input"
                        placeholder="Select date of placement"
                        value={placement.dateOfPlacement}
                        onChange={(e) => handleInputChange('placement', 'dateOfPlacement', e.target.value, index)}
                        required
                      />
                    </div>
                  </div>
                ))}
                <button className="add-button" onClick={addPlacement}>
                  <Plus className="add-icon" />
                  Add Placement
                </button>
              </div>
            )}
          </div>

          {/* Project Details Section */}
          <div>
            <div className="collapsible-header" onClick={() => toggleSection('projectDetails')}>
              <span>Project Details</span>
              <span className={`collapsible-arrow ${openSection === 'projectDetails' ? 'open' : ''}`}>
                ▼
              </span>
            </div>
            {openSection === 'projectDetails' && (
              <div className="collapsible-content">
                {formData.projectDetails.map((project, index) => (
                  <div key={index} className="entry">
                    {formData.projectDetails.length > 1 && (
                      <button className="remove-button" onClick={() => removeProject(index)}>
                        <Trash2 className="trash-icon" />
                        Remove Project
                      </button>
                    )}
                    <div className="form-field">
                      <input
                        type="text"
                        className="form-input"
                        placeholder="Enter project title"
                        value={project.title}
                        onChange={(e) => handleInputChange('projectDetails', 'title', e.target.value, index)}
                        required
                      />
                    </div>
                    <div className="form-field">
                      <input
                        type="url"
                        className="form-input"
                        placeholder="Enter project URL"
                        value={project.url}
                        onChange={(e) => handleInputChange('projectDetails', 'url', e.target.value, index)}
                        required
                      />
                    </div>
                    <div className="form-field-row date-row">
                      <div className="date-field-wrapper">
                        <label htmlFor={"project-start-date-" + index} className="form-label start-date-label">Start Date:</label>
                        <div className="form-field start-date-input">
                          <input
                            type="date"
                            id={"project-start-date-" + index}
                            className="form-input"
                            placeholder="Select start date"
                            value={project.startDate}
                            onChange={(e) => handleInputChange('projectDetails', 'startDate', e.target.value, index)}
                            required
                          />
                        </div>
                      </div>
                      <div className="date-field-wrapper">
                        <label htmlFor={"project-end-date-" + index} className="form-label end-date-label">End Date:</label>
                        <div className="form-field end-date-input">
                          <input
                            type="date"
                            id={"project-end-date-" + index}
                            className="form-input"
                            placeholder="Select end date"
                            value={project.endDate}
                            onChange={(e) => handleInputChange('projectDetails', 'endDate', e.target.value, index)}
                            required
                          />
                        </div>
                      </div>
                    </div>
                    <div className="form-field">
                      <textarea
                        className="form-textarea"
                        placeholder="Enter project description"
                        value={project.description}
                        onChange={(e) => handleInputChange('projectDetails', 'description', e.target.value, index)}
                        required
                      />
                    </div>
                    <div className="form-field-row">
                      <div className="form-field file-input-wrapper report-upload">
                        <input
                          type="file"
                          className="form-input"
                          accept=".pdf,.doc,.docx"
                          onChange={(e) => handleFileChange('projectDetails', 'document', e, index)}
                          required
                        />
                        <span className="file-input-label">
                          <Upload className="upload-icon" />
                          Upload report
                        </span>
                      </div>
                      <span className="status-label">Status: Pending</span>
                    </div>
                    {project.document && (
                      <div className="uploaded-file">
                        <span>{project.document.name}</span>
                        <button
                          className="remove-file-button"
                          onClick={() => removeFile('projectDetails', 'document', index)}
                        >
                          <X className="cross-icon" />
                        </button>
                      </div>
                    )}
                  </div>
                ))}
                <button className="add-button" onClick={addProject}>
                  <Plus className="add-icon" />
                  Add Project
                </button>
              </div>
            )}
          </div>

          {/* Competitions Section */}
          <div>
            <div className="collapsible-header" onClick={() => toggleSection('competitions')}>
              <span>Competitions</span>
              <span className={`collapsible-arrow ${openSection === 'competitions' ? 'open' : ''}`}>
                ▼
              </span>
            </div>
            {openSection === 'competitions' && (
              <div className="collapsible-content">
                {formData.competitions.map((competition, index) => (
                  <div key={index} className="entry">
                    {formData.competitions.length > 1 && (
                      <button className="remove-button" onClick={() => removeCompetition(index)}>
                        <Trash2 className="trash-icon" />
                        Remove Competition
                      </button>
                    )}
                    <div className="form-field">
                      <input
                        type="text"
                        className="form-input"
                        placeholder="Enter competition title"
                        value={competition.title}
                        onChange={(e) => handleInputChange('competitions', 'title', e.target.value, index)}
                        required
                      />
                    </div>
                    <div className="form-field">
                      <input
                        type="text"
                        className="form-input"
                        placeholder="Enter organizer name"
                        value={competition.organizer}
                        onChange={(e) => handleInputChange('competitions', 'organizer', e.target.value, index)}
                        required
                      />
                    </div>
                    <div className="form-field">
                      <input
                        type="text"
                        className="form-input"
                        placeholder="Enter winning details (e.g., 1st Place, Special Mention)"
                        value={competition.winningDetails}
                        onChange={(e) => handleInputChange('competitions', 'winningDetails', e.target.value, index)}
                        required
                      />
                    </div>
                    <div className="form-field-row date-row">
                      <div className="date-field-wrapper">
                        <label htmlFor={"competitions-start-date-" + index} className="form-label start-date-label">Start Date:</label>
                        <div className="form-field start-date-input">
                          <input
                            type="date"
                            id={"competitions-start-date-" + index}
                            className="form-input"
                            placeholder="Select start date"
                            value={competition.startDate}
                            onChange={(e) => handleInputChange('competitions', 'startDate', e.target.value, index)}
                            required
                          />
                        </div>
                      </div>
                      <div className="date-field-wrapper">
                        <label htmlFor={"competitions-end-date-" + index} className="form-label end-date-label">End Date:</label>
                        <div className="form-field end-date-input">
                          <input
                            type="date"
                            id={"competitions-end-date-" + index}
                            className="form-input"
                            placeholder="Select end date"
                            value={competition.endDate}
                            onChange={(e) => handleInputChange('competitions', 'endDate', e.target.value, index)}
                            required
                          />
                        </div>
                      </div>
                    </div>
                    <div className="form-field">
                      <textarea
                        className="form-textarea"
                        placeholder="Enter competition description"
                        value={competition.description}
                        onChange={(e) => handleInputChange('competitions', 'description', e.target.value, index)}
                        required
                      />
                    </div>
                    <div className="form-field-row">
                      <div className="form-field file-input-wrapper competition-upload">
                        <input
                          type="file"
                          className="form-input"
                          accept=".pdf,.doc,.docx,.jpg,.png"
                          onChange={(e) => handleFileChange('competitions', 'upload', e, index)}
                          required
                        />
                        <span className="file-input-label">
                          <Upload className="upload-icon" />
                          Upload file
                        </span>
                      </div>
                      <span className="status-label">Status: Pending</span>
                    </div>
                    {competition.upload && (
                      <div className="uploaded-file">
                        <span>{competition.upload.name}</span>
                        <button
                          className="remove-file-button"
                          onClick={() => removeFile('competitions', 'upload', index)}
                        >
                          <X className="cross-icon" />
                        </button>
                      </div>
                    )}
                  </div>
                ))}
                <button className="add-button" onClick={addCompetition}>
                  <Plus className="add-icon" />
                  Add Competition
                </button>
              </div>
            )}
          </div>
          {/* Internship Section */}
          <div>
            <div className="collapsible-header" onClick={() => toggleSection('internship')}>
              <span>Internship</span>
              <span className={`collapsible-arrow ${openSection === 'internship' ? 'open' : ''}`}>
                ▼
              </span>
            </div>
            {openSection === 'internship' && (
              <div className="collapsible-content">
                {formData.internship.map((internship, index) => (
                  <div key={index} className="entry">
                    {formData.internship.length > 1 && (
                      <button className="remove-button" onClick={() => removeInternship(index)}>
                        <Trash2 className="trash-icon" />
                        Remove Internship
                      </button>
                    )}
                    <div className="form-field">
                      <input
                        type="text"
                        className="form-input"
                        placeholder="Enter company name"
                        value={internship.companyName}
                        onChange={(e) => handleInputChange('internship', 'companyName', e.target.value, index)}
                        required
                      />
                    </div>
                    <div className="form-field">
                      <input
                        type="text"
                        className="form-input"
                        placeholder="Enter your role"
                        value={internship.role}
                        onChange={(e) => handleInputChange('internship', 'role', e.target.value, index)}
                        required
                      />
                    </div>
                    <div className="form-field-row date-row">
                      <div className="date-field-wrapper">
                        <label htmlFor={"internship-start-date-" + index} className="form-label start-date-label">Start Date:</label>
                        <div className="form-field start-date-input">
                          <input
                            type="date"
                            id={"internship-start-date-" + index}
                            className="form-input"
                            placeholder="Select start date"
                            value={internship.startDate}
                            onChange={(e) => handleInputChange('internship', 'startDate', e.target.value, index)}
                            required
                          />
                        </div>
                      </div>
                      <div className="date-field-wrapper">
                        <label htmlFor={"internship-end-date-" + index} className="form-label end-date-label">End Date:</label>
                        <div className="form-field end-date-input">
                          <input
                            type="date"
                            id={"internship-end-date-" + index}
                            className="form-input"
                            placeholder="Select end date"
                            value={internship.endDate}
                            onChange={(e) => handleInputChange('internship', 'endDate', e.target.value, index)}
                            required
                          />
                        </div>
                      </div>
                    </div>
                    <div className="form-field">
                      <textarea
                        className="form-textarea"
                        placeholder="Enter internship description"
                        value={internship.description}
                        onChange={(e) => handleInputChange('internship', 'description', e.target.value, index)}
                        required
                      />
                    </div>
                    <div className="form-field-row">
                      <div className="form-field file-input-wrapper internship-upload">
                        <input
                          type="file"
                          className="form-input"
                          accept=".pdf,.jpg,.png"
                          onChange={(e) => handleFileChange('internship', 'certificate', e, index)}
                          required
                        />
                        <span className="file-input-label">
                          <Upload className="upload-icon" />
                          Upload certificate
                        </span>
                      </div>
                      <span className="status-label">Status: Pending</span>
                    </div>
                    {internship.certificate && (
                                           <div className="uploaded-file">
                        <span>{internship.certificate.name}</span>
                        <button
                          className="remove-file-button"
                          onClick={() => removeFile('internship', 'certificate', index)}
                        >
                          <X className="cross-icon" />
                        </button>
                      </div>
                    )}
                  </div>
                ))}
                <button className="add-button" onClick={addInternship}>
                  <Plus className="add-icon" />
                  Add Internship
                </button>
              </div>
            )}
          </div>

         {/* Online Course Section */}
         <div>
            <div className="collapsible-header" onClick={() => toggleSection('onlineCourse')}>
              <span>Online Course</span>
              <span className={`collapsible-arrow ${openSection === 'onlineCourse' ? 'open' : ''}`}>
                ▼
              </span>
            </div>
            {openSection === 'onlineCourse' && (
              <div className="collapsible-content">
                {formData.onlineCourse.map((course, index) => (
                  <div key={index} className="entry">
                    {formData.onlineCourse.length > 1 && (
                      <button className="remove-button" onClick={() => removeOnlineCourse(index)}>
                        <Trash2 className="trash-icon" />
                        Remove Online Course
                      </button>
                    )}
                    <div className="form-field">
                      <input
                        type="text"
                        className="form-input"
                        placeholder="Enter course name"
                        value={course.courseName}
                        onChange={(e) => handleInputChange('onlineCourse', 'courseName', e.target.value, index)}
                        required
                      />
                    </div>
                    <div className="form-field-row date-row">
                      <div className="date-field-wrapper">
                        <label htmlFor={"online-course-start-date-" + index} className="form-label start-date-label">Start Date:</label>
                        <div className="form-field start-date-input">
                          <input
                            type="date"
                            id={"online-course-start-date-" + index}
                            className="form-input"
                            placeholder="Select start date"
                            value={course.startDate}
                            onChange={(e) => handleInputChange('onlineCourse', 'startDate', e.target.value, index)}
                            required
                          />
                        </div>
                      </div>
                      <div className="date-field-wrapper">
                        <label htmlFor={"online-course-end-date-" + index} className="form-label end-date-label">End Date:</label>
                        <div className="form-field end-date-input">
                          <input
                            type="date"
                            id={"online-course-end-date-" + index}
                            className="form-input"
                            placeholder="Select end date"
                            value={course.endDate}
                            onChange={(e) => handleInputChange('onlineCourse', 'endDate', e.target.value, index)}
                            required
                          />
                        </div>
                      </div>
                    </div>
                    <div className="form-field">
                      <textarea
                        className="form-textarea"
                        placeholder="Enter course description"
                        value={course.description}
                        onChange={(e) => handleInputChange('onlineCourse', 'description', e.target.value, index)}
                        required
                      />
                    </div>
                    <div className="form-field-row">
                      <div className="form-field file-input-wrapper course-upload">
                        <input
                          type="file"
                          className="form-input"
                          accept=".pdf,.jpg,.png"
                          onChange={(e) => handleFileChange('onlineCourse', 'certifications', e, index)}
                          required
                        />
                        <span className="file-input-label">
                          <Upload className="upload-icon" />
                          Upload certificate
                        </span>
                      </div>
                      <span className="status-label">Status: Pending</span>
                    </div>
                    {course.certifications && (
                      <div className="uploaded-file">
                        <span>{course.certifications.name}</span>
                        <button
                          className="remove-file-button"
                          onClick={() => removeFile('onlineCourse', 'certifications', index)}
                        >
                          <X className="cross-icon" />
                        </button>
                      </div>
                    )}
                  </div>
                ))}
                <button className="add-button" onClick={addOnlineCourse}>
                  <Plus className="add-icon" />
                  Add Online Course
                </button>
              </div>
            )}
          </div>

          {/* Product Development Section */}
          <div>
            <div className="collapsible-header" onClick={() => toggleSection('productDevelopment')}>
              <span>Product Development</span>
              <span className={`collapsible-arrow ${openSection === 'productDevelopment' ? 'open' : ''}`}>
                ▼
              </span>
            </div>
            {openSection === 'productDevelopment' && (
              <div className="collapsible-content">
                {formData.productDevelopment.map((product, index) => (
                  <div key={index} className="entry">
                    {formData.productDevelopment.length > 1 && (
                      <button className="remove-button" onClick={() => removeProductDevelopment(index)}>
                        <Trash2 className="trash-icon" />
                        Remove Product Development
                      </button>
                    )}
                    <div className="form-field">
                      <input
                        type="text"
                        className="form-input"
                        placeholder="Enter product name"
                        value={product.productName}
                        onChange={(e) => handleInputChange('productDevelopment', 'productName', e.target.value, index)}
                        required
                      />
                    </div>
                    <div className="form-field-row date-row">
                      <div className="date-field-wrapper">
                        <label htmlFor={"product-development-start-date-" + index} className="form-label start-date-label">Start Date:</label>
                        <div className="form-field start-date-input">
                          <input
                            type="date"
                            id={"product-development-start-date-" + index}
                            className="form-input"
                            placeholder="Select start date"
                            value={product.startDate}
                            onChange={(e) => handleInputChange('productDevelopment', 'startDate', e.target.value, index)}
                            required
                          />
                        </div>
                      </div>
                      <div className="date-field-wrapper">
                        <label htmlFor={"product-development-end-date-" + index} className="form-label end-date-label">End Date:</label>
                        <div className="form-field end-date-input">
                          <input
                            type="date"
                            id={"product-development-end-date-" + index}
                            className="form-input"
                            placeholder="Select end date"
                            value={product.endDate}
                            onChange={(e) => handleInputChange('productDevelopment', 'endDate', e.target.value, index)}
                            required
                          />
                        </div>
                      </div>
                    </div>
                    <div className="form-field">
                      <textarea
                        className="form-textarea"
                        placeholder="Enter product details"
                        value={product.details}
                        onChange={(e) => handleInputChange('productDevelopment', 'details', e.target.value, index)}
                        required
                      />
                    </div>
                    <div className="form-field-row">
                      <div className="form-field file-input-wrapper product-upload">
                        <input
                          type="file"
                          className="form-input"
                          accept=".pdf,.jpg,.png"
                          onChange={(e) => handleFileChange('productDevelopment', 'upload', e, index)}
                          required
                        />
                        <span className="file-input-label">
                          <Upload className="upload-icon" />
                          Upload report
                        </span>
                      </div>
                      <span className="status-label">Status: Pending</span>
                    </div>
                    {product.upload && (
                      <div className="uploaded-file">
                        <span className="uploaded-file-name">{product.upload.name}</span>
                        <button
                          className="remove-file-button"
                          onClick={() => removeFile('productDevelopment', 'upload', index)}
                        >
                          ✕
                        </button>
                      </div>
                    )}
                  </div>
                ))}
                <button className="add-button" onClick={addProductDevelopment}>
                  <Plus className="add-icon" />
                  Add Product Development
                </button>
              </div>
            )}
          </div>

          {/* Languages Section */}
          <div>
            <div className="collapsible-header" onClick={() => toggleSection('languages')}>
              <span>Languages</span>
              <span className={`collapsible-arrow ${openSection === 'languages' ? 'open' : ''}`}>
                ▼
              </span>
            </div>
            {openSection === 'languages' && (
              <div className="collapsible-content">
                <div className="form-field">
                  <input
                    type="text"
                    className="form-input"
                    placeholder="Enter language (e.g., English,Tamil ,Hindi)"
                    value={formData.languages.language}
                    onChange={(e) => handleInputChange('languages', 'language', e.target.value)}
                    required
                  />
                </div>
              </div>
            )}
          </div>

          {/* Button Container for Submit, Preview, and Download */}
          <div className="button-container">
            <button className="submit-button" onClick={handleSubmit}>
              Submit
            </button>
            <div className="secondary-buttons">
              <button className="preview-button" onClick={handlePreview}>
                Preview
              </button>
              <button className="download-button" onClick={handleDownload}>
                Download
              </button>
            </div>
          </div>
        </div>

        {/* Success Notification Card */}
        {showSuccess && (
          <div className="success-modal">
            <div className="success-checkmark">✔</div>
            <div className="success-title">Success!</div>
            <div className="success-message">Achievements submitted successfully.</div>
          </div>
        )}

        {/* Preview Modal */}
       {showPreview && (
          <div className="preview-modal-container">
            <div className="preview-modal">
              <button className="preview-modal-close" onClick={handleClosePreview}>
                ✕
              </button>
              <div id="resume-preview" className="resume-container">
                {/* Header Section */}
                <div className="resume-header">
                  <h1>{formData.personalDetails.name || 'Your Name'}</h1>
                  <h2>Professional Profile</h2>
                  {photoUrl && <img src={photoUrl} alt="Profile" className="resume-photo" />}
                  <div className="resume-contact">
                    <p>{formData.personalDetails.phoneNumber || '+123-456-7890'}</p>
                    <p>{formData.personalDetails.email || 'your.email@example.com'}</p>
                    <p>{formData.personalDetails.githubUrl || 'github.com/yourusername'}</p>
                    <p>{formData.personalDetails.linkedinUrl || 'linkedin.com/in/yourusername'}</p>
                    {/* <p>123 Anywhere St., Any City</p> */}
                    {/* <p>www.yourwebsite.com</p> */}
                  </div>
                </div>

                {/* Profile Section */}
                <div className="resume-section">
                  <h3>Profile</h3>
                  <p>
                    {formData.profileSummary.description ||
                      'Dynamic and creative Software developer with a degree in Mechatronics Engineering. Eager to leverage my technical expertise, programming skills and creative problemsolving abilities in a challenging environment that fosters growth and innovation.'}
                  </p>
                </div>

                {/* Education Section */}
                {formData.academicDetails.length > 0 && (
                  <div className="resume-section">
                    <h3>Education</h3>
                    {formData.academicDetails.map((academic, index) => (
                      <div key={index} className="resume-item">
                        <h4>{academic.institutionName || 'Bannari Amman Institute of Technology'}</h4>
                        <p>Year of Passing: {academic.yearOfPassing || '2025'}</p>
                        <p>Percentage: {academic.percentage || 'N/A'}%</p>
                      </div>
                    ))}
                  </div>
                )}

                {/* Skills Section */}
                {skills.length > 0 && (
                  <div className="resume-section">
                    <h3>Skills</h3>
                    <ul>
                      {skills.map((skill, index) => (
                        <li key={index}>{skill}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Work Experience Section */}
                {(formData.internship.length > 0 || formData.productDevelopment.length > 0) && (
                  <div className="resume-section">
                    <h3>Work Experience</h3>
                    {formData.internship.map((internship, index) => (
                      <div key={index} className="resume-item">
                        <h4>{internship.companyName || 'Company'} - {internship.role || 'Role'}</h4>
                        <p>
                          {internship.startDate || 'N/A'} - {internship.endDate || 'Present'}
                        </p>
                        <ul>
                          <li>{internship.description || 'Contributed to company projects.'}</li>
                        </ul>
                      </div>
                    ))}
                    {/* {formData.productDevelopment.map((product, index) => (
                      <div key={index} className="resume-item">
                        <h4>{product.productName || 'Product'} - Product Developer</h4>
                        <p>
                          {product.startDate || 'N/A'} - {product.endDate || 'Present'}
                        </p>
                        <ul>
                          <li>{product.details || 'Developed and launched a product.'}</li>
                        </ul>
                      </div>
                    ))} */}
                  </div>
                )}

                {/* Projects Section */}
                {formData.projectDetails.length > 0 && (
                  <div className="resume-section">
                    <h3>Projects</h3>
                    {formData.projectDetails.map((project, index) => (
                      <div key={index} className="resume-item">
                        <h4>{project.title || 'Untitled Project'}</h4>
                        <p>URL: {project.url || 'N/A'}</p>
                        <ul>
                          <li>{project.description || 'N/A'}</li>
                        </ul>
                      </div>
                    ))}
                  </div>
                )}

                {/* Competitions Section */}
                {formData.competitions.length > 0 && (
                  <div className="resume-section">
                    <h3>Competitions</h3>
                    {formData.competitions.map((competition, index) => (
                      <div key={index} className="resume-item">
                        <h4>{competition.title || `Competition ${index + 1}`}</h4>
                        <p>Organizer: {competition.organizer || 'N/A'}</p>
                        <p>Winning Details: {competition.winningDetails || 'N/A'}</p>
                        <p>
                          {competition.startDate || 'N/A'} - {competition.endDate || 'N/A'}
                        </p>
                        <ul>
                          <li>{competition.description || 'Participated in a competition.'}</li>
                        </ul>
                      </div>
                    ))}
                  </div>
                )}

               {/* Online Courses Section */}
          {formData.onlineCourse.length > 0 && (
            <div className="resume-section">
              <h3>Online Courses</h3>
              {formData.onlineCourse.map((course, index) => (
                <div key={index} className="resume-item">
                  <h4>{course.courseName || 'Untitled Course'}</h4>
                  <p>
                    {course.startDate || 'N/A'} - {course.endDate || 'N/A'}
                  </p>
                  <ul>
                    <li>{course.description || 'Completed an online course.'}</li>
                  </ul>
                </div>
              ))}
            </div>
          )}

                {/* Languages Section */}
                {languages.length > 0 && (
                  <div className="resume-section">
                    <h3>Languages</h3>
                    <ul>
                      {languages.map((lang, index) => (
                        <li key={index}>{lang} </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </>
  );
};

export default Achievements;