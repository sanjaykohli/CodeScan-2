import { useState, useMemo } from "react";
import { X, FileText, FileCode, File, FileJson, FileTerminal, FileSpreadsheet } from "lucide-react";

interface FileListModalProps {
  files: string[];
  isOpen: boolean;
  onClose: () => void;
}

const FileListModal = ({ files, isOpen, onClose }: FileListModalProps) => {
  const [searchTerm, setSearchTerm] = useState("");
  const [filter, setFilter] = useState("all");
  
  // Always calculate fileCounts unconditionally
  const fileCounts = useMemo(() => {
    const counts: Record<string, number> = {
      all: files.length,
      js: 0,
      ts: 0,
      py: 0,
      java: 0,
      css: 0,
      html: 0,
      json: 0,
      other: 0
    };
    
    files.forEach(file => {
      const extension = file.split('.').pop()?.toLowerCase() || '';
      
      if (['js', 'jsx'].includes(extension)) counts.js++;
      else if (['ts', 'tsx'].includes(extension)) counts.ts++;
      else if (['py'].includes(extension)) counts.py++;
      else if (['java'].includes(extension)) counts.java++;
      else if (['css', 'scss', 'less'].includes(extension)) counts.css++;
      else if (['html', 'htm'].includes(extension)) counts.html++;
      else if (['json', 'yml', 'yaml'].includes(extension)) counts.json++;
      else counts.other++;
    });
    
    return counts;
  }, [files]);
  
  // Always calculate filteredFiles unconditionally
  const filteredFiles = useMemo(() => {
    return files.filter(file => {
      const matchesSearch = file.toLowerCase().includes(searchTerm.toLowerCase());
      const matchesFilter = filter === "all" || file.endsWith(`.${filter}`);
      return matchesSearch && matchesFilter;
    });
  }, [files, searchTerm, filter]);
  
  // Get icon for file
  const getFileIcon = (fileName: string) => {
    const extension = fileName.split('.').pop()?.toLowerCase() || '';
    
    if (['js', 'jsx'].includes(extension)) return <FileCode className="text-yellow-400" />;
    if (['ts', 'tsx'].includes(extension)) return <FileCode className="text-blue-500" />;
    if (['py'].includes(extension)) return <FileTerminal className="text-blue-300" />;
    if (['java'].includes(extension)) return <FileCode className="text-red-500" />;
    if (['css', 'scss', 'less'].includes(extension)) return <File className="text-blue-400" />;
    if (['html', 'htm'].includes(extension)) return <File className="text-orange-500" />;
    if (['json', 'yml', 'yaml'].includes(extension)) return <FileJson className="text-green-500" />;
    if (['md'].includes(extension)) return <FileSpreadsheet className="text-blue-300" />;
    
    return <FileText className="text-gray-400" />;
  };
  
  if (!isOpen) return null;
  
  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-gray-900 border border-gray-700 rounded-xl max-w-3xl w-full max-h-[90vh] flex flex-col">
        <div className="border-b border-gray-700 p-4 flex justify-between items-center">
          <h3 className="text-xl font-bold">Scanned Files</h3>
          <button 
            onClick={onClose}
            className="p-1 rounded-full hover:bg-gray-800 transition-colors"
          >
            <X size={24} />
          </button>
        </div>
        
        <div className="p-4 border-b border-gray-700">
          <div className="flex justify-between mb-4">
            <div className="relative w-full max-w-md">
              <input
                type="text"
                placeholder="Search files..."
                className="w-full bg-gray-800 border border-gray-700 rounded-lg py-2 pl-10 pr-4 focus:outline-none focus:ring-2 focus:ring-blue-500"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
              <svg 
                className="absolute left-3 top-2.5 text-gray-500" 
                width="20" 
                height="20" 
                viewBox="0 0 24 24"
              >
                <path 
                  fill="currentColor" 
                  d="M15.5 14h-.79l-.28-.27A6.471 6.471 0 0 0 16 9.5A6.5 6.5 0 1 0 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5S14 7.01 14 9.5S11.99 14 9.5 14z"
                />
              </svg>
            </div>
            
            <div className="ml-4">
              <select
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                className="bg-gray-800 border border-gray-700 rounded-lg py-2 px-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="all">All Files ({fileCounts.all})</option>
                <option value="js">JavaScript ({fileCounts.js})</option>
                <option value="ts">TypeScript ({fileCounts.ts})</option>
                <option value="py">Python ({fileCounts.py})</option>
                <option value="java">Java ({fileCounts.java})</option>
                <option value="css">CSS ({fileCounts.css})</option>
                <option value="html">HTML ({fileCounts.html})</option>
                <option value="json">Config ({fileCounts.json})</option>
                <option value="other">Other ({fileCounts.other})</option>
              </select>
            </div>
          </div>
          
          <div className="grid grid-cols-4 gap-2">
            {Object.entries(fileCounts).map(([type, count]) => (
              <div 
                key={type}
                onClick={() => setFilter(type === "all" ? "all" : type)}
                className={`p-2 rounded-lg cursor-pointer transition-colors ${
                  filter === type || (type !== "all" && filter === type) 
                    ? "bg-blue-500/20 border border-blue-500" 
                    : "bg-gray-800 hover:bg-gray-700"
                }`}
              >
                <div className="text-sm font-medium capitalize">{type}</div>
                <div className="text-lg font-bold">{count}</div>
              </div>
            ))}
          </div>
        </div>
        
        <div className="overflow-y-auto flex-1">
          <div className="grid grid-cols-1 gap-1 p-4">
            {filteredFiles.length > 0 ? (
              filteredFiles.map((file, index) => (
                <div 
                  key={index} 
                  className="flex items-center p-3 bg-gray-800 rounded-lg hover:bg-gray-700 transition-colors"
                >
                  <div className="mr-3">
                    {getFileIcon(file)}
                  </div>
                  <div className="font-mono text-sm truncate">{file}</div>
                </div>
              ))
            ) : (
              <div className="text-center py-8 text-gray-500">
                No files match your search
              </div>
            )}
          </div>
        </div>
        
        <div className="p-4 border-t border-gray-700 text-sm text-gray-400">
          Scanned {files.length} files in total
        </div>
      </div>
    </div>
  );
};

export default FileListModal;