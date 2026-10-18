/**
 * Computer Networks Mini-Project: Secure 3-Tier Web Application
 * Student Information System & Live 3-Tier Packet Inspector
 */

(function () {
  'use strict';

  // State
  let currentUser = { role: 'guest', username: 'guest', full_name: 'Guest User', authenticated: false };
  let studentsData = [];
  let statsData = {};
  let auditLogsData = [];
  let activeStudent = null;

  // Determine API base dynamically to work across port 5000, port 8000, port 80, port 8080, or local dev
  function getApiBase() {
    const p = window.location.port;
    if (p === '5000' || p === '8000' || p === '80' || p === '8080') {
      return '';
    }
    return `${window.location.protocol}//${window.location.hostname || 'localhost'}:5000`;
  }
  const API_BASE = getApiBase();

  // Helper
  const $ = id => document.getElementById(id);

  function showNotification(message, type = 'info') {
    const banner = $('portalNotification');
    if (!banner) return;
    banner.textContent = message;
    banner.className = `portal-notification notification-${type}`;
    banner.hidden = false;
    clearTimeout(banner._timeout);
    banner._timeout = setTimeout(() => {
      banner.hidden = true;
    }, 4500);
  }

  function setLoginModalAlert(message, type = 'error') {
    const alertBox = $('loginModalAlert');
    if (!alertBox) return;
    if (!message) {
      alertBox.style.display = 'none';
      alertBox.textContent = '';
      return;
    }
    alertBox.style.display = 'block';
    alertBox.textContent = message;
    if (type === 'error') {
      alertBox.style.background = '#fee2e2';
      alertBox.style.color = '#991b1b';
      alertBox.style.border = '1px solid #f87171';
    } else {
      alertBox.style.background = '#ecfdf5';
      alertBox.style.color = '#065f46';
      alertBox.style.border = '1px solid #6ee7b7';
    }
  }

  // ==========================================
  // NAVIGATION & SECTION SWITCHING
  // ==========================================
  function navigateToSection(sectionId) {
    window.location.hash = sectionId;
    if (typeof window.showSection === 'function') {
      window.showSection(sectionId);
    } else {
      document.querySelectorAll('.page-section').forEach(sec => {
        const active = sec.id === sectionId;
        sec.classList.toggle('active-section', active);
        sec.hidden = !active;
      });
      document.querySelectorAll('.nav-item[data-section]').forEach(item => {
        const active = item.dataset.section === sectionId;
        item.classList.toggle('active', active);
      });
    }
  }

  // ==========================================
  // LIVE 3-TIER PACKET INSPECTOR ANIMATION
  // ==========================================
  function tracePacketFlow(stepName, details = {}, outcome = 'ALLOW') {
    const traceBox = $('liveTraceOutput');
    const badge = $('liveTraceBadge');
    const pathText = $('liveTracePath');

    if (!traceBox) return;

    const time = new Date().toLocaleTimeString();
    badge.textContent = outcome === 'ALLOW' ? 'ALLOWED' : 'BLOCKED';
    badge.className = `decision-badge ${outcome === 'ALLOW' ? 'allow' : 'deny'}`;

    if (outcome === 'DENY') {
      pathText.innerHTML = `<span class="hop error">Client (192.168.1.20)</span> ➔ ❌ <span class="hop error">Database Tier (10.0.3.10:3306)</span> [DROPPED BY FIREWALL]`;
    } else {
      pathText.innerHTML = `<span class="hop">Client (192.168.1.20)</span> ➔ <span class="hop">Web:443</span> ➔ <span class="hop">App:5000</span> ➔ <span class="hop">DB:3306</span>`;
    }

    const logEntry = document.createElement('div');
    logEntry.className = `trace-entry trace-${outcome.toLowerCase()}`;
    logEntry.innerHTML = `
      <div class="trace-entry-head">
        <span class="trace-timestamp">[${time}]</span>
        <strong>${stepName}</strong>
        <span class="status-pill status-${outcome.toLowerCase()}">${outcome}</span>
      </div>
      <div class="trace-entry-body">
        <small>${details.summary || ''}</small>
        <div class="trace-hops">
          <span>Client: <code>${details.client_ip || '192.168.1.20'}</code></span>
          <span>Web Ingress: <code>Nginx :80/443</code></span>
          <span>App Logic: <code>Flask :5000</code></span>
          <span>Data Storage: <code>MySQL :3306</code></span>
        </div>
      </div>
    `;

    traceBox.prepend(logEntry);
    while (traceBox.children.length > 8) {
      traceBox.removeChild(traceBox.lastChild);
    }
  }

  // ==========================================
  // AUTHENTICATION & SESSIONS
  // ==========================================
  async function checkAuth() {
    try {
      const res = await fetch(`${API_BASE}/api/auth/me`, { credentials: 'include' });
      if (res.ok) {
        const data = await res.json();
        currentUser = data.user;
        currentUser.authenticated = data.authenticated;
        renderAuthStatus();
      }
    } catch (e) {
      console.warn('Auth check skipped:', e);
    }
  }

  function renderAuthStatus() {
    const userBadge = $('userRoleBadge');
    const userName = $('currentUserName');
    const loginBtn = $('openLoginModalBtn');
    const logoutBtn = $('logoutBtn');
    const addStudentBtn = $('openAddStudentModal');

    if (userName) userName.textContent = currentUser.full_name || currentUser.username;
    if (userBadge) {
      userBadge.textContent = currentUser.role.toUpperCase();
      userBadge.className = `role-badge role-${currentUser.role}`;
    }

    if (currentUser.authenticated) {
      if (loginBtn) loginBtn.hidden = true;
      if (logoutBtn) logoutBtn.hidden = false;
      if (addStudentBtn) {
        addStudentBtn.disabled = currentUser.role !== 'admin';
        addStudentBtn.title = currentUser.role === 'admin' ? 'Add student record' : 'Only Administrator can add students';
      }
    } else {
      if (loginBtn) loginBtn.hidden = false;
      if (logoutBtn) logoutBtn.hidden = true;
      if (addStudentBtn) {
        addStudentBtn.disabled = true;
        addStudentBtn.title = 'Please log in as Administrator to add students';
      }
    }
  }

  async function login(username, password) {
    const submitBtn = $('loginSubmitBtn');
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.textContent = 'Signing in...';
    }
    setLoginModalAlert('');

    try {
      const res = await fetch(`${API_BASE}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ username, password })
      });

      const data = await res.json();
      if (!res.ok) {
        setLoginModalAlert(data.error || 'Invalid credentials or login failed.', 'error');
        showNotification(data.error || 'Login failed', 'error');
        tracePacketFlow('Authentication Attempt', { summary: `Login failed for '${username}'`, client_ip: '192.168.1.20' }, 'DENY');
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.textContent = 'Sign in';
        }
        return false;
      }

      setLoginModalAlert(`Welcome, ${data.user.full_name}! Redirecting...`, 'success');
      currentUser = data.user;
      currentUser.authenticated = true;
      renderAuthStatus();

      tracePacketFlow('Authentication', { summary: `User '${username}' authenticated as ${currentUser.role}`, client_ip: '192.168.1.20' }, 'ALLOW');

      setTimeout(() => {
        closeModal('loginModal');
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.textContent = 'Sign in';
        }
        navigateToSection('portal');
        showNotification(`Welcome, ${currentUser.full_name}! (Role: ${currentUser.role.toUpperCase()})`, 'success');
        loadStudents();
        loadStats();
        loadAuditLogs();
      }, 400);

      return true;
    } catch (err) {
      console.error('Login error:', err);
      setLoginModalAlert('Network error: Unable to reach Application Tier. Ensure server is running.', 'error');
      showNotification('Network connection error', 'error');
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Sign in';
      }
      return false;
    }
  }

  async function logout() {
    try {
      await fetch(`${API_BASE}/api/auth/logout`, { method: 'POST', credentials: 'include' });
      currentUser = { role: 'guest', username: 'guest', full_name: 'Guest User', authenticated: false };
      renderAuthStatus();
      showNotification('Signed out successfully.', 'info');
      tracePacketFlow('Session Terminated', { summary: 'User session destroyed', client_ip: '192.168.1.20' }, 'ALLOW');
      loadStudents();
    } catch (e) {
      console.error(e);
    }
  }

  // ==========================================
  // DATA FETCHING & CRUD
  // ==========================================
  async function loadStudents() {
    const search = $('studentSearchInput')?.value.trim() || '';
    const dept = $('deptFilterSelect')?.value || '';
    const status = $('statusFilterSelect')?.value || '';

    const params = new URLSearchParams();
    if (search) params.append('search', search);
    if (dept && dept !== 'All') params.append('department', dept);
    if (status && status !== 'All') params.append('status', status);

    try {
      const res = await fetch(`${API_BASE}/api/students?${params.toString()}`, { credentials: 'include' });
      if (!res.ok) throw new Error('Failed to fetch students');
      const data = await res.json();
      studentsData = data.students;
      renderStudentsTable();
      tracePacketFlow('SELECT students', {
        summary: `Retrieved ${studentsData.length} records through 3-tier pipeline`,
        client_ip: '192.168.1.20'
      }, 'ALLOW');
    } catch (err) {
      console.warn('Could not load students API:', err);
    }
  }

  function renderStudentsTable() {
    const tbody = $('studentsTableBody');
    const countBadge = $('studentsCountBadge');
    if (!tbody) return;

    tbody.innerHTML = '';
    if (countBadge) countBadge.textContent = `${studentsData.length} Students`;

    if (studentsData.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" class="text-center empty-state">No matching student records found.</td></tr>`;
      return;
    }

    studentsData.forEach(student => {
      const tr = document.createElement('tr');
      const gpaScore = Number(student.gpa).toFixed(2);
      const attScore = Number(student.attendance_pct).toFixed(1);

      tr.innerHTML = `
        <td><strong class="mono-code">${student.roll_number}</strong></td>
        <td>
          <div class="student-name-cell">
            <span>${student.name}</span>
            <small class="student-email">${student.email}</small>
          </div>
        </td>
        <td><span class="dept-tag">${student.department}</span></td>
        <td>Year ${student.year} · Sem ${student.semester}</td>
        <td><span class="score-badge gpa">${gpaScore}</span></td>
        <td>
          <div class="att-wrap">
            <span class="score-badge att">${attScore}%</span>
            <div class="progress-bar-wrap"><div class="progress-bar-fill" style="width: ${Math.min(attScore, 100)}%"></div></div>
          </div>
        </td>
        <td><span class="status-pill status-${student.status.toLowerCase().replace(/\s+/g, '-')}">${student.status}</span></td>
        <td class="action-cell">
          <button class="btn-icon view-student-btn" data-id="${student.id}" title="View Academic Profile" aria-label="View Student">
            <svg class="icon" viewBox="0 0 24 24"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>
          </button>
          ${currentUser.role === 'admin' ? `
            <button class="btn-icon edit-student-btn" data-id="${student.id}" title="Edit Student" aria-label="Edit Student">
              <svg class="icon" viewBox="0 0 24 24"><path d="M12 20h9M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>
            </button>
            <button class="btn-icon delete-student-btn" data-id="${student.id}" title="Delete Student" aria-label="Delete Student">
              <svg class="icon" viewBox="0 0 24 24"><path d="M3 6h18m-2 0v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6m3 0V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2M10 11v6m4-6v6"/></svg>
            </button>
          ` : ''}
        </td>
      `;
      tbody.appendChild(tr);
    });

    // Attach row events
    tbody.querySelectorAll('.view-student-btn').forEach(btn => {
      btn.addEventListener('click', () => viewStudent(btn.dataset.id));
    });
    tbody.querySelectorAll('.edit-student-btn').forEach(btn => {
      btn.addEventListener('click', () => openEditStudentModal(btn.dataset.id));
    });
    tbody.querySelectorAll('.delete-student-btn').forEach(btn => {
      btn.addEventListener('click', () => confirmDeleteStudent(btn.dataset.id));
    });
  }

  async function loadStats() {
    try {
      const res = await fetch(`${API_BASE}/api/stats`, { credentials: 'include' });
      if (!res.ok) return;
      statsData = await res.json();

      if ($('metricTotalStudents')) $('metricTotalStudents').textContent = statsData.total_students;
      if ($('metricActiveStudents')) $('metricActiveStudents').textContent = statsData.active_students;
      if ($('metricAvgGpa')) $('metricAvgGpa').textContent = statsData.avg_gpa;
      if ($('metricAvgAttendance')) $('metricAvgAttendance').textContent = `${statsData.avg_attendance}%`;
    } catch (e) {
      console.warn('Could not load stats:', e);
    }
  }

  async function loadAuditLogs() {
    try {
      const res = await fetch(`${API_BASE}/api/security/audit-log?limit=15`, { credentials: 'include' });
      if (!res.ok) return;
      const data = await res.json();
      auditLogsData = data.logs;
      renderAuditLogs();
    } catch (e) {
      console.warn('Could not load audit logs:', e);
    }
  }

  function renderAuditLogs() {
    const list = $('auditLogsList');
    if (!list) return;
    list.innerHTML = '';

    if (!auditLogsData || auditLogsData.length === 0) {
      list.innerHTML = `<div class="empty-state">No security audit logs yet.</div>`;
      return;
    }

    auditLogsData.forEach(log => {
      const item = document.createElement('div');
      item.className = `audit-log-item log-${log.decision.toLowerCase()}`;
      item.innerHTML = `
        <div class="audit-head">
          <span class="audit-decision pill-${log.decision.toLowerCase()}">${log.decision}</span>
          <span class="audit-time">${log.timestamp}</span>
          <strong>${log.action}</strong>
        </div>
        <div class="audit-route">
          <code>${log.tier_source}</code> ➔ <code>${log.tier_dest} :${log.port}</code>
          <span class="audit-ip">Client: ${log.client_ip}</span>
        </div>
        <p class="audit-details">${log.details || ''}</p>
      `;
      list.appendChild(item);
    });
  }

  async function viewStudent(id) {
    try {
      const res = await fetch(`${API_BASE}/api/students/${id}`, { credentials: 'include' });
      if (!res.ok) throw new Error('Could not retrieve student details');
      const student = await res.json();
      activeStudent = student;

      $('profileRoll').textContent = student.roll_number;
      $('profileName').textContent = student.name;
      $('profileEmail').textContent = student.email;
      $('profileDept').textContent = student.department;
      $('profileYearSem').textContent = `Year ${student.year}, Semester ${student.semester}`;
      $('profileGpa').textContent = Number(student.gpa).toFixed(2);
      $('profileAttendance').textContent = `${Number(student.attendance_pct).toFixed(1)}%`;
      $('profileStatus').textContent = student.status;
      $('profilePhone').textContent = student.phone || 'N/A';

      const coursesList = $('profileCoursesList');
      if (coursesList) {
        coursesList.innerHTML = '';
        if (student.courses && student.courses.length > 0) {
          student.courses.forEach(c => {
            const div = document.createElement('div');
            div.className = 'course-badge-item';
            div.innerHTML = `
              <strong>${c.course_code}: ${c.course_name}</strong>
              <span>${c.credits} Credits · Instructor: ${c.instructor}</span>
              <span class="grade-tag">Grade: ${c.grade} · Attendance: ${c.attendance_pct}%</span>
            `;
            coursesList.appendChild(div);
          });
        } else {
          coursesList.innerHTML = `<p class="helper-text">Enrolled in standard core curriculum.</p>`;
        }
      }

      openModal('viewStudentModal');
      tracePacketFlow(`GET student ${student.roll_number}`, {
        summary: `Retrieved records for ${student.name}`,
        client_ip: '192.168.1.20'
      }, 'ALLOW');
    } catch (e) {
      showNotification('Error viewing student profile', 'error');
    }
  }

  function openEditStudentModal(id) {
    const student = studentsData.find(s => String(s.id) === String(id));
    if (!student) return;

    $('editStudentId').value = student.id;
    $('editRollNumber').value = student.roll_number;
    $('editName').value = student.name;
    $('editEmail').value = student.email;
    $('editDepartment').value = student.department;
    $('editYear').value = student.year;
    $('editSemester').value = student.semester;
    $('editGpa').value = student.gpa;
    $('editAttendance').value = student.attendance_pct;
    $('editStatus').value = student.status;
    $('editPhone').value = student.phone || '';

    openModal('editStudentModal');
  }

  async function saveStudentEdit(e) {
    e.preventDefault();
    const id = $('editStudentId').value;
    const payload = {
      name: $('editName').value.trim(),
      email: $('editEmail').value.trim(),
      department: $('editDepartment').value.trim(),
      year: parseInt($('editYear').value, 10),
      semester: parseInt($('editSemester').value, 10),
      gpa: parseFloat($('editGpa').value),
      attendance_pct: parseFloat($('editAttendance').value),
      status: $('editStatus').value,
      phone: $('editPhone').value.trim()
    };

    try {
      const res = await fetch(`${API_BASE}/api/students/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(payload)
      });

      const data = await res.json();
      if (!res.ok) {
        showNotification(data.error || 'Failed to update student', 'error');
        return;
      }

      showNotification('Student record updated successfully', 'success');
      closeModal('editStudentModal');
      tracePacketFlow(`UPDATE student id=${id}`, { summary: `Updated details for ${payload.name}` }, 'ALLOW');
      loadStudents();
      loadStats();
      loadAuditLogs();
    } catch (e) {
      showNotification('Error updating student', 'error');
    }
  }

  async function saveNewStudent(e) {
    e.preventDefault();
    const payload = {
      roll_number: $('newRollNumber').value.trim(),
      name: $('newName').value.trim(),
      email: $('newEmail').value.trim(),
      department: $('newDepartment').value.trim(),
      year: parseInt($('newYear').value, 10),
      semester: parseInt($('newSemester').value, 10),
      gpa: parseFloat($('newGpa').value),
      attendance_pct: parseFloat($('newAttendance').value),
      status: $('newStatus').value,
      phone: $('newPhone').value.trim()
    };

    try {
      const res = await fetch(`${API_BASE}/api/students`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(payload)
      });

      const data = await res.json();
      if (!res.ok) {
        showNotification(data.error || 'Failed to add student', 'error');
        return;
      }

      showNotification(`Student '${payload.name}' added successfully`, 'success');
      $('addStudentForm').reset();
      closeModal('addStudentModal');
      tracePacketFlow(`INSERT student ${payload.roll_number}`, { summary: `Created new student record` }, 'ALLOW');
      loadStudents();
      loadStats();
      loadAuditLogs();
    } catch (e) {
      showNotification('Error creating student', 'error');
    }
  }

  async function confirmDeleteStudent(id) {
    const student = studentsData.find(s => String(s.id) === String(id));
    if (!student) return;

    if (!confirm(`Are you sure you want to permanently delete student '${student.name}' (${student.roll_number})?`)) {
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/api/students/${id}`, {
        method: 'DELETE',
        credentials: 'include'
      });

      const data = await res.json();
      if (!res.ok) {
        showNotification(data.error || 'Could not delete student', 'error');
        return;
      }

      showNotification(`Student record removed.`, 'success');
      tracePacketFlow(`DELETE student id=${id}`, { summary: `Deleted student ${student.roll_number}` }, 'ALLOW');
      loadStudents();
      loadStats();
      loadAuditLogs();
    } catch (e) {
      showNotification('Error deleting student', 'error');
    }
  }

  // ==========================================
  // NETWORK SECURITY PENETRATION TEST
  // ==========================================
  async function testDirectDatabaseAttack() {
    const btn = $('btnTestDirectDb');
    if (btn) btn.disabled = true;

    try {
      const res = await fetch(`${API_BASE}/api/security/test-direct-db`, {
        method: 'POST',
        credentials: 'include'
      });
      const data = await res.json();

      tracePacketFlow('Penetration Test: Client Direct to MySQL :3306', {
        summary: data.reason,
        client_ip: '192.168.1.20'
      }, 'DENY');

      showNotification('Direct connection attempt to Database Tier was BLOCKED by Firewall!', 'error');

      const resultBox = $('securityTestResult');
      if (resultBox) {
        resultBox.hidden = false;
        resultBox.innerHTML = `
          <div class="security-alert-box alert-denied">
            <div class="alert-title">
              <svg class="icon" viewBox="0 0 24 24"><path d="m12 3 8 3v6c0 4-4 7-8 9-4-2-8-5-8-9V6Z"/><path d="m9 12 6 0"/></svg>
              <strong>FIREWALL DECISION: ${data.badge}</strong>
            </div>
            <p><strong>Attempted Vector:</strong> <code>Client (192.168.1.20) ➔ Database (10.0.3.10:3306)</code></p>
            <p><strong>Matched Policy:</strong> <code>${data.firewall_rule_matched}</code></p>
            <p><strong>Architecture Defense:</strong> ${data.reason}</p>
            <div class="security-recs">
              <strong>Security Invariant Enforced:</strong>
              <p>${data.security_recommendation}</p>
            </div>
          </div>
        `;
      }

      loadAuditLogs();
    } catch (e) {
      console.error(e);
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  async function checkTierDiagnostics() {
    try {
      const res = await fetch(`${API_BASE}/api/network/inspect`, { credentials: 'include' });
      if (!res.ok) return;
      const diag = await res.json();

      if ($('webTierStatus')) {
        $('webTierStatus').textContent = diag.tier1_web.status;
        $('webTierStatus').className = `status-pill status-active`;
      }
      if ($('appTierStatus')) {
        $('appTierStatus').textContent = diag.tier2_app.status;
        $('appTierStatus').className = `status-pill status-active`;
      }
      if ($('dbTierStatus')) {
        $('dbTierStatus').textContent = diag.tier3_db.status;
        $('dbTierStatus').className = `status-pill ${diag.tier3_db.status === 'ONLINE' ? 'status-active' : 'status-error'}`;
      }
      if ($('dbTierDialect')) {
        $('dbTierDialect').textContent = `${diag.tier3_db.dialect} (${diag.tier3_db.latency_ms || 0}ms)`;
      }
    } catch (e) {
      console.warn('Diagnostics endpoint offline:', e);
    }
  }

  // ==========================================
  // MODALS
  // ==========================================
  function openModal(id) {
    const modal = $(id);
    if (modal) {
      modal.hidden = false;
      modal.setAttribute('aria-modal', 'true');
      modal.querySelector('input, button')?.focus();
    }
  }

  function closeModal(id) {
    const modal = $(id);
    if (modal) {
      modal.hidden = true;
      modal.removeAttribute('aria-modal');
    }
  }

  // Init event handlers
  function initEvents() {
    // Close modal buttons
    document.querySelectorAll('[data-close-modal]').forEach(btn => {
      btn.addEventListener('click', () => {
        const modalId = btn.dataset.closeModal;
        closeModal(modalId);
      });
    });

    // Login modal open
    $('openLoginModalBtn')?.addEventListener('click', () => {
      setLoginModalAlert('');
      openModal('loginModal');
    });

    // Logout button
    $('logoutBtn')?.addEventListener('click', logout);

    // Quick demo login buttons (auto-fills and submits)
    $('btnQuickLoginAdmin')?.addEventListener('click', () => {
      $('loginUsername').value = 'admin';
      $('loginPassword').value = 'Admin@123';
      login('admin', 'Admin@123');
    });

    $('btnQuickLoginStudent')?.addEventListener('click', () => {
      $('loginUsername').value = 'student';
      $('loginPassword').value = 'Student@123';
      login('student', 'Student@123');
    });

    // Login form submit
    $('loginForm')?.addEventListener('submit', e => {
      e.preventDefault();
      const u = $('loginUsername').value.trim();
      const p = $('loginPassword').value;
      login(u, p);
    });

    // Search and filters
    $('studentSearchInput')?.addEventListener('input', () => {
      clearTimeout(window._searchTimer);
      window._searchTimer = setTimeout(loadStudents, 250);
    });
    $('deptFilterSelect')?.addEventListener('change', loadStudents);
    $('statusFilterSelect')?.addEventListener('change', loadStudents);

    // Student CRUD
    $('openAddStudentModal')?.addEventListener('click', () => {
      if (currentUser.role !== 'admin') {
        showNotification('Action denied: Only administrators can add new students.', 'error');
        return;
      }
      openModal('addStudentModal');
    });

    $('addStudentForm')?.addEventListener('submit', saveNewStudent);
    $('editStudentForm')?.addEventListener('submit', saveStudentEdit);

    // Security Penetration Test
    $('btnTestDirectDb')?.addEventListener('click', testDirectDatabaseAttack);
    $('btnTestLegitimateRoute')?.addEventListener('click', () => {
      loadStudents();
      showNotification('Legitimate request followed Web ➔ App ➔ DB path successfully!', 'success');
    });

    // Refresh buttons
    $('refreshAuditBtn')?.addEventListener('click', () => {
      loadAuditLogs();
      checkTierDiagnostics();
      showNotification('Audits and tier diagnostics refreshed', 'info');
    });
  }

  // Bootstrap when DOM ready
  document.addEventListener('DOMContentLoaded', () => {
    initEvents();
    checkAuth();
    loadStudents();
    loadStats();
    loadAuditLogs();
    checkTierDiagnostics();
  });

})();
