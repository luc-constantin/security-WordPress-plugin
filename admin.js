jQuery(function ($) {
  function setAllToggles(state) {
    $('[data-ag-toggle] input[type="checkbox"]').each(function () {
      $(this).prop('checked', state);
    });
  }

  $('#ag-enable-all').on('click', function () {
    setAllToggles(true);
  });

  $('#ag-disable-all').on('click', function () {
    setAllToggles(false);
  });

  // Spinner on "Run Check Now" button (do NOT block submit)
  const $runBtn = $('#ag-run-now');
  if ($runBtn.length) {
    $runBtn.on('click', function () {
      $runBtn.addClass('is-loading');

      // Delay disabling so the form submit is not interrupted
      window.setTimeout(function () {
        $runBtn.prop('disabled', true);
      }, 150);
    });
  }
});
