/**
 * SSH Ping Challenges - Update Challenge
 *
 * Provides dynamic preview functionality for SSH ping challenge descriptions.
 * Replaces :pod_id: tokens with actual pod numbers in real-time as the user types.
 *
 */

CTFd.plugin.run((_CTFd) => {
    "use strict";

    const $ = _CTFd.lib.$;
    _CTFd.lib.markdown();

    /**
     * Update the pod description previews based on current editor content
     */
    function updatePreviews() {
        const description = $('#new-desc-editor').val() || '';
        // Update previews
        const preview1 = description.replace(/:pod_id:/g, '1');
        const preview2 = description.replace(/:pod_id:/g, '2');

        $('#preview-pod-1').html(preview1 || 'No description yet...');
        $('#preview-pod-2').html(preview2 || 'No description yet...');
    }

    /**
     * Initialize the plugin when document is ready
     */
    $(document).ready(() => {
        $('#new-desc-editor').on('input', updatePreviews);
        updatePreviews(); // Initial count
    });
});
