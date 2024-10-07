const childSchema = new mongoose.Schema({
    name: String,
    dob: Date,
    ic_no: String,  
    gender: String,  
    tempat_lahir: String,  
    keturunan: String,  
    warganegara: String,  
    pribumi_sarawak: String,
    propict: String,  
    class_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Class', required: false },
    receiptUploaded: { type: Boolean, default: false },
    parent_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Parent' },
    attendanceRecords: [{
        date: Date,
        status: String,  
        additionalInfo: String
    }],
    siblings: [{
        nama: String,
        dob: Date,
        status: { type: String, enum: ['Masih Belajar', 'Bekerja', 'Tidak Bekerja'] },
        tahap_pendidikan: { type: String, enum: ['Prasekolah', 'Pendidikan Rendah', 'Pendidikan Menengah', 'Pendidikan Pra-Universiti', 'Pengajian Tinggi'] }
    }]
});

const classSchema = new mongoose.Schema({
    classname: String,
    teachersincharge: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Teacher' }],
});

const userSchema = new mongoose.Schema({
    firstname: String,
    lastname: String,
    username: String,
    email: { type: String, required: true, index: true, unique: true },
    password: String,
    role: { type: String, enum: ['parent', 'teacher', 'admin'], required: true },
    nama_bapa: String,
    ic_no_bapa: String,
    warganegara_bapa: String,
    phone_bapa: String,
    pekerjaan_bapa: String,
    nama_ibu: String,
    ic_no_ibu: String,
    pekerjaan_ibu: String,
    warganegara_ibu: String,
    phone_ibu: String,
    phone: String,
    subject: String,
    address: String,
});

const parentSchema = new mongoose.Schema({
    user_id:  { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    children:  [{ type: mongoose.Schema.Types.ObjectId, ref: 'Child' }]
});

const teacherSchema = new mongoose.Schema({
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    class_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Class', required: true }
});

const fileSchema = new mongoose.Schema({
    childId: { type: mongoose.Schema.Types.ObjectId, ref: 'Child', required: true },
    filePath: String,
    originalName: String,
    thumbnailPath: String,
    uploadDate: { type: Date, default: Date.now }
});

const attendanceSchema = new mongoose.Schema({
    student_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Child', required: true },
    status: { type: String, enum: ['HADIR', 'TIDAK HADIR'], required: true },
    additional_info: { type: String },
    date: { type: Date, required: true }
});

const paymentSchema = new mongoose.Schema({
    childId: { type: mongoose.Schema.Types.ObjectId, ref: 'Child'}, 
    products: [{
        name: String,
        desc: String,
        type: { type: String },
        color: String,
        size: { type: String },
        quantity: { type: Number, default: 1 },
        price: Number
    }],
    isProduct: { type: Boolean },
    totalAmount: { type: Number }, 
    date: { type: Date, default: Date.now }, 
    timestamp: { type: Date, default: Date.now },
    file: String,
    status: { type: String, enum: ['Pay Now', 'Pending', 'Paid', 'Invalid'] } 
});