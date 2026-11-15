'use client';

import { useMemo, useState } from 'react';
import {
    Box, MenuItem, Table, TableBody, TableCell, TableContainer, TableHead,
    TablePagination, TableRow, TableSortLabel, TextField,
} from '@mui/material';
import type { Analysis, TrafficLabel } from './types';

type SortField = 'row' | 'sample_name' | 'score' | 'confidence';
const emptyFilters = { query: '', prediction: 'all', match: 'all' };
const menuItemSx = { '&.Mui-selected, &.Mui-selected:hover': { bgcolor: '#DDF1EA' } };

function Label({ label }: { label: TrafficLabel | null }) {
    if (label === null) return <span className="text-gray-400">Not provided</span>;
    return (
        <span className={`inline-block rounded-lg px-3 py-1 font-medium ${label === 'benign' ? 'bg-[#DDF1EA] text-[#127A63]' : 'bg-red-50 text-red-700'}`}>
            {label === 'benign' ? 'Benign' : 'Malicious'}
        </span>
    );
}

export default function PredictionTable({ rows }: { rows: Analysis['results'] }) {
    const [filters, setFilters] = useState(emptyFilters);
    const [sort, setSort] = useState<{ field: SortField; direction: number }>({ field: 'row', direction: 1 });
    const [page, setPage] = useState(0);
    const [rowsPerPage, setRowsPerPage] = useState(10);

    const filtered = useMemo(() => {
        const query = filters.query.trim().toLowerCase();
        return rows.filter((row) => (
            (!query || row.sample_name.toLowerCase().includes(query) || String(row.row).includes(query))
            && (filters.prediction === 'all' || row.label === filters.prediction)
            && (filters.match === 'all' || (filters.match === 'unknown'
                ? row.correct === null : row.correct === (filters.match === 'correct')))
        )).sort((a, b) => {
            const difference = sort.field === 'sample_name'
                ? a.sample_name.localeCompare(b.sample_name, undefined, { numeric: true })
                : a[sort.field] - b[sort.field];
            return difference * sort.direction || a.row - b.row;
        });
    }, [rows, filters, sort]);

    const currentPage = Math.min(page, Math.max(0, Math.ceil(filtered.length / rowsPerPage) - 1));
    const visible = filtered.slice(currentPage * rowsPerPage, (currentPage + 1) * rowsPerPage);

    function updateFilter(field: keyof typeof filters, value: string) {
        setFilters({ ...filters, [field]: value });
        setPage(0);
    }

    function clearFilters() {
        setFilters(emptyFilters);
        setPage(0);
    }

    function sortBy(field: SortField) {
        setSort({ field, direction: sort.field === field ? -sort.direction : 1 });
        setPage(0);
    }

    return (
        <Box component="section" className="min-w-0 overflow-hidden rounded-3xl border border-[#E3EBE7]" sx={{
            fontFamily: 'inherit', color: '#3D3D3D',
            '& .MuiTableCell-root, & .MuiInputBase-root, & .MuiFormLabel-root, & .MuiTablePagination-root, & .MuiTablePagination-selectLabel, & .MuiTablePagination-displayedRows': { fontFamily: 'inherit', fontSize: '1rem' },
            '& .MuiOutlinedInput-root': { bgcolor: 'white', borderRadius: '12px' },
            '& .MuiOutlinedInput-root.Mui-focused .MuiOutlinedInput-notchedOutline': { borderColor: '#127A63' },
            '& .MuiInputLabel-root.Mui-focused': { color: '#127A63' },
        }}>
            <div className="flex flex-col gap-5 bg-[#F2F5F4] p-5 sm:p-6">
                <h3 className="text-2xl font-semibold">Individual predictions</h3>
                <TextField
                    fullWidth label="Search samples" placeholder="Sample name or row number"
                    value={filters.query} onChange={(event) => updateFilter('query', event.target.value)}
                />
                <div className="grid gap-4 sm:grid-cols-2">
                    <TextField select label="Prediction" value={filters.prediction}
                        onChange={(event) => updateFilter('prediction', event.target.value)}>
                        <MenuItem value="all" sx={menuItemSx}>All predictions</MenuItem>
                        <MenuItem value="benign" sx={menuItemSx}>Benign</MenuItem>
                        <MenuItem value="malicious" sx={menuItemSx}>Malicious</MenuItem>
                    </TextField>
                    <TextField select label="Ground-truth match" value={filters.match}
                        onChange={(event) => updateFilter('match', event.target.value)}>
                        <MenuItem value="all" sx={menuItemSx}>All records</MenuItem>
                        <MenuItem value="correct" sx={menuItemSx}>Correct</MenuItem>
                        <MenuItem value="incorrect" sx={menuItemSx}>Incorrect</MenuItem>
                        <MenuItem value="unknown" sx={menuItemSx}>No ground truth</MenuItem>
                    </TextField>
                </div>
                <div className="flex flex-wrap items-center justify-between gap-3 text-base">
                    <p role="status" className="text-gray-500">{filtered.length.toLocaleString()} of {rows.length.toLocaleString()} records</p>
                    <button type="button" onClick={clearFilters} className="cursor-pointer font-medium text-[#127A63] hover:underline">Clear filters</button>
                </div>
            </div>

            <TableContainer sx={{ maxHeight: 560 }} tabIndex={0} role="region" aria-label="Individual predictions table">
                <Table stickyHeader sx={{
                    minWidth: 860,
                    '& .MuiTableCell-root': { borderColor: '#E3EBE7', p: 2 },
                    '& .MuiTableCell-head': { bgcolor: '#EDF5F1', fontWeight: 600, whiteSpace: 'nowrap' },
                    '& .MuiTableSortLabel-root.Mui-active, & .MuiTableSortLabel-root.Mui-active .MuiTableSortLabel-icon': { color: '#127A63' },
                    '& .MuiTableRow-root:hover': { bgcolor: '#F0F8F4' },
                }}>
                    <caption className="sr-only">Predictions, scores, confidence and ground truth</caption>
                    <TableHead>
                        <TableRow>
                            <TableCell sortDirection={sort.field === 'sample_name' ? (sort.direction === 1 ? 'asc' : 'desc') : false}>
                                <TableSortLabel active={sort.field === 'sample_name'}
                                    direction={sort.field === 'sample_name' && sort.direction === -1 ? 'desc' : 'asc'}
                                    onClick={() => sortBy('sample_name')}>Sample</TableSortLabel>
                            </TableCell>
                            <TableCell>Prediction</TableCell>
                            {(['score', 'confidence'] as const).map((field) => (
                                <TableCell key={field} sortDirection={sort.field === field ? (sort.direction === 1 ? 'asc' : 'desc') : false}>
                                    <TableSortLabel active={sort.field === field}
                                        direction={sort.field === field && sort.direction === -1 ? 'desc' : 'asc'}
                                        onClick={() => sortBy(field)}>
                                        {field === 'score' ? 'Malicious score' : 'Confidence'}
                                    </TableSortLabel>
                                </TableCell>
                            ))}
                            <TableCell>Ground truth</TableCell>
                            <TableCell>Match</TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {visible.map((row) => (
                            <TableRow key={row.row}>
                                <TableCell component="th" scope="row">
                                    <span className="block max-w-56 break-words font-medium">{row.sample_name}</span>
                                    <span className="mt-1 block text-sm text-gray-400">Row {row.row.toLocaleString()}</span>
                                </TableCell>
                                <TableCell><Label label={row.label} /></TableCell>
                                <TableCell sx={{ fontVariantNumeric: 'tabular-nums' }}>{(row.score * 100).toFixed(4)}%</TableCell>
                                <TableCell sx={{ fontVariantNumeric: 'tabular-nums' }}>{(row.confidence * 100).toFixed(4)}%</TableCell>
                                <TableCell><Label label={row.ground_truth} /></TableCell>
                                <TableCell sx={{ color: row.correct === null ? '#9CA3AF' : row.correct ? '#127A63' : '#B43C3C' }}>
                                    {row.correct === null ? '—' : row.correct ? 'Correct' : 'Incorrect'}
                                </TableCell>
                            </TableRow>
                        ))}
                        {visible.length === 0 && <TableRow><TableCell colSpan={6} sx={{ py: 5, textAlign: 'center' }}>No matching records</TableCell></TableRow>}
                    </TableBody>
                </Table>
            </TableContainer>
            <TablePagination
                component="div" count={filtered.length} page={currentPage} rowsPerPage={rowsPerPage}
                rowsPerPageOptions={[10, 25, 50, 100]} showFirstButton showLastButton
                onPageChange={(_, nextPage) => setPage(nextPage)}
                onRowsPerPageChange={(event) => { setRowsPerPage(Number(event.target.value)); setPage(0); }}
                sx={{
                    bgcolor: '#F2F5F4',
                    '& .MuiTablePagination-toolbar': { flexWrap: 'wrap', justifyContent: 'flex-end', px: 2, py: 1 },
                    '& .MuiTablePagination-spacer': { display: 'none' },
                    '& .MuiTablePagination-actions button': { color: '#127A63' },
                    '& .MuiTablePagination-actions button.Mui-disabled': { color: '#B5C4BD' },
                }}
            />
            <p className="border-t border-[#E3EBE7] px-5 py-4 text-sm leading-relaxed text-gray-500">
                Score is the probability of malicious traffic. Confidence is the probability assigned to the predicted class.
            </p>
        </Box>
    );
}
