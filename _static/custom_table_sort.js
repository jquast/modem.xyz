// Custom sorting and copy-to-clipboard for MUD server tables
$(document).ready(function() {
    setTimeout(function() {
        $('table.sphinx-datatable').each(function() {
            if ($.fn.DataTable.isDataTable(this)) {
                var table = $(this).DataTable();
                var headers = [];

                $(this).find('thead th').each(function() {
                    headers.push($(this).text().trim());
                });

                // Server list: sort by Players (descending)
                if (headers.includes('Players') && headers.includes('Name')) {
                    var playersIdx = headers.indexOf('Players');
                    table.order([playersIdx, 'desc']).draw();
                }
                // Fingerprint table: sort by Servers count (descending)
                else if (headers.includes('Fingerprint') && headers.includes('Servers')) {
                    var serversIdx = headers.indexOf('Servers');
                    table.order([serversIdx, 'desc']).draw();
                }
            }
        });

        // Add copy buttons to telnet links in tables
        $('table a[href^="telnet://"]').each(function() {
            var $link = $(this);
            if ($link.next('.copy-btn').length) return;
            var href = $link.attr('href');
            var match = href.match(/^telnet:\/\/([^:\/]+)(?::(\d+))?/);
            if (!match) return;
            var host = match[1];
            var port = match[2] || '23';
            var $btn = $('<button>')
                .addClass('copy-btn')
                .attr('data-host', host)
                .attr('data-port', port)
                .attr('title', 'Copy host and port')
                .attr('aria-label', 'Copy ' + host + ' port ' + port + ' to clipboard')
                .html('<span class="copy-icon" aria-hidden="true">&#x1F4CB;</span>');
            $link.after($btn);
        });
    }, 200);

    // Copy button click handler (delegated for dynamic content)
    $(document).on('click', '.copy-btn', function(e) {
        e.preventDefault();
        e.stopPropagation();
        var host = $(this).data('host');
        var port = $(this).data('port');
        var text = host + ' ' + port;
        var $btn = $(this);

        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(function() {
                $btn.find('.copy-icon').html('&#x2713;');
                setTimeout(function() {
                    $btn.find('.copy-icon').html('&#x1F4CB;');
                }, 1500);
            });
        } else {
            // Fallback for older browsers
            var $temp = $('<textarea>');
            $('body').append($temp);
            $temp.val(text).select();
            document.execCommand('copy');
            $temp.remove();
            $btn.find('.copy-icon').html('&#x2713;');
            setTimeout(function() {
                $btn.find('.copy-icon').html('&#x1F4CB;');
            }, 1500);
        }
    });
});
